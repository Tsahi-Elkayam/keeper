-- name: printers
-- description: Every printer and what is known about it from the newest scans: model, serial number, firmware, state and the printed page count - a network printer's own counter, or the pages a computer sent to a print queue. Network printers first, then the queues on computers (USB ones marked usb). --kind usb|queue|network narrows it.
-- param: kind optional
WITH latest AS (
    SELECT rs.run_id, rs.entity_type, rs.entity_key, rs.attrs, rs.observed_at, lr.instance AS inst
    FROM row_seen rs
    JOIN latest_run lr ON lr.run_id = rs.run_id
),
network AS (
    -- One printer is read several ways (ports, IPP, SNMP): what each learned is put together, the SNMP model first.
    SELECT 'network' AS kind, inst AS integration, entity_key AS printer,
           COALESCE(MAX(json_extract(attrs, '$.model')), MAX(json_extract(attrs, '$."printer-make-and-model"'))) AS model,
           MAX(json_extract(attrs, '$.serialNumber')) AS serial,
           MAX(json_extract(attrs, '$."printer-firmware-string-version"')) AS firmware,
           COALESCE(MAX(json_extract(attrs, '$.status')),
                    CASE MAX(json_extract(attrs, '$."printer-state"')) WHEN 3 THEN 'idle' WHEN 4 THEN 'printing' WHEN 5 THEN 'stopped' END) AS state,
           MAX(json_extract(attrs, '$.pageCount')) AS pages_printed,
           MAX(json_extract(attrs, '$.pageCountUnit')) AS pages_unit,
           MAX(json_extract(attrs, '$.sysLocation')) AS location,
           MAX(observed_at) AS seen
    FROM latest
    WHERE entity_type = 'printer'
    GROUP BY inst, entity_key
),
queues AS (
    SELECT CASE WHEN json_extract(q.attrs, '$.usb') = 1 THEN 'usb' ELSE 'queue' END AS kind, q.inst AS integration,
           json_extract(q.attrs, '$.host') || ' / ' || json_extract(q.attrs, '$.name') AS printer,
           COALESCE(json_extract(q.attrs, '$.vendor') || ' ' || json_extract(q.attrs, '$.model'), json_extract(q.attrs, '$.deviceUri')) AS model,
           json_extract(q.attrs, '$.serial') AS serial,
           NULL AS firmware,
           json_extract(q.attrs, '$.state') AS state,
           (SELECT json_extract(u.attrs, '$.pages') FROM latest u
             WHERE u.entity_type = 'printer-usage' AND u.inst = q.inst AND u.entity_key = q.entity_key) AS pages_printed,
           CASE WHEN EXISTS (SELECT 1 FROM latest u WHERE u.entity_type = 'printer-usage' AND u.inst = q.inst AND u.entity_key = q.entity_key)
                THEN 'pages sent from this computer' END AS pages_unit,
           NULL AS location,
           q.observed_at AS seen
    FROM latest q
    WHERE q.entity_type = 'queue'
)
SELECT * FROM (SELECT * FROM network UNION ALL SELECT * FROM queues)
WHERE (:kind IS NULL OR kind = :kind)
ORDER BY CASE kind WHEN 'network' THEN 0 WHEN 'usb' THEN 1 ELSE 2 END, printer;
