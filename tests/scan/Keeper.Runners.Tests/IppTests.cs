using System.Text;
using Keeper.Runners.Printer;

namespace Keeper.Runners.Tests;

public sealed class IppTests
{
    [Fact]
    public void The_request_is_a_get_printer_attributes_for_the_printer_uri_and_nothing_else()
    {
        var request = Ipp.GetPrinterAttributesRequest("ipp://192.0.2.50:631/ipp/print");

        Assert.Equal([0x01, 0x01, 0x00, 0x0B], request[..4]);                       // IPP 1.1, Get-Printer-Attributes
        Assert.Equal(0x03, request[^1]);                                              // end of attributes
        var text = Encoding.UTF8.GetString(request);
        Assert.Contains("ipp://192.0.2.50:631/ipp/print", text, StringComparison.Ordinal);
        Assert.Contains("requested-attributes", text, StringComparison.Ordinal);
        Assert.Equal(0x01, request[8]);                                               // the operation attributes begin right after the header
    }

    [Fact]
    public void The_operation_is_only_ever_get_printer_attributes()
    {
        // 0x000B. Print-Job is 0x0002, Create-Job 0x0005, Cancel-Job 0x0008: none can be built.
        var operation = Ipp.GetPrinterAttributesRequest("ipp://192.0.2.50/ipp/print")[2..4];

        Assert.Equal([0x00, 0x0B], operation);
        Assert.DoesNotContain(typeof(Ipp).GetMethods().Select(m => m.Name), n => n.Contains("Print", StringComparison.Ordinal) && n != "GetPrinterAttributesRequest");
    }

    [Fact]
    public void Attributes_come_back_by_name_with_single_values_as_values_and_repeated_ones_as_lists()
    {
        var bytes = new IppResponseBuilder().PrinterGroup()
            .Text(0x41, "printer-info", "Reception laser")
            .Text(0x41, "printer-make-and-model", "HP LaserJet Pro M404")
            .Keyword("uri-security-supported", "none", "tls")
            .Keyword("printer-state-reasons", "none")
            .Integer("queued-job-count", 3)
            .Integer("marker-levels", 80, 15, 4)
            .Enum("printer-state", 3)
            .Boolean("printer-is-accepting-jobs", true)
            .Uri("printer-uri-supported", "ipp://192.0.2.50/ipp/print", "ipps://192.0.2.50/ipp/print")
            .Build();

        var response = Ipp.Parse(bytes);

        Assert.Equal(0, response.StatusCode);
        Assert.Equal("HP LaserJet Pro M404", response.Attributes["printer-make-and-model"]!.ToString());
        Assert.Equal(3, (long)response.Attributes["queued-job-count"]!);
        Assert.Equal(["none", "tls"], response.Attributes["uri-security-supported"]!.AsArray().Select(n => n!.ToString()));
        Assert.Equal([80L, 15L, 4L], response.Attributes["marker-levels"]!.AsArray().Select(n => (long)n!));
        Assert.Equal(3L, (long)response.Attributes["printer-state"]!);
        Assert.True((bool)response.Attributes["printer-is-accepting-jobs"]!);
        Assert.Equal("none", response.Attributes["printer-state-reasons"]!.ToString());
        Assert.Equal(2, response.Attributes["printer-uri-supported"]!.AsArray().Count);
    }

    [Fact]
    public void Collections_are_skipped_whole_including_nested_ones_and_what_follows_still_parses()
    {
        var bytes = new IppResponseBuilder().PrinterGroup()
            .Collection("media-col-default")
            .Text(0x41, "printer-info", "after the collection")
            .Build();

        var response = Ipp.Parse(bytes);

        Assert.Equal("after the collection", response.Attributes["printer-info"]!.ToString());
        Assert.Contains("media-col-default", response.Attributes.Keys);
    }

    [Fact]
    public void An_attribute_the_printer_has_no_value_for_is_null_not_an_error()
    {
        var response = Ipp.Parse(new IppResponseBuilder().PrinterGroup().NoValue("printer-firmware-string-version").Build());

        Assert.True(response.Attributes.ContainsKey("printer-firmware-string-version"));
        Assert.Null(response.Attributes["printer-firmware-string-version"]);
    }

    [Fact]
    public void A_refusal_from_the_printer_is_a_status_not_an_exception()
    {
        var response = Ipp.Parse(new IppResponseBuilder(status: 0x0406).Build());

        Assert.Equal(0x0406, response.StatusCode);
        Assert.False(response.Successful);
        Assert.True(Ipp.Parse(new IppResponseBuilder(status: 0x0001).Build()).Successful);   // successful-ok-ignored-or-substituted-attributes
    }

    [Fact]
    public void Attributes_before_the_printer_group_are_not_mistaken_for_the_printer()
    {
        var bytes = new IppResponseBuilder().Build();   // only the operation attributes

        Assert.Empty(Ipp.Parse(bytes).Attributes);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(3)]
    [InlineData(8)]
    public void Too_little_data_is_a_format_error(int length)
    {
        Assert.Throws<FormatException>(() => Ipp.Parse(new byte[length]));
    }

    [Fact]
    public void A_response_cut_off_in_the_middle_of_an_attribute_is_a_format_error_never_a_partial_pass()
    {
        var truncated = new IppResponseBuilder().PrinterGroup().Text(0x41, "printer-info", "Reception laser").BuildTruncated();

        Assert.Throws<FormatException>(() => Ipp.Parse(truncated));
    }

    [Fact]
    public void A_length_that_runs_past_the_data_is_a_format_error()
    {
        var bytes = new IppResponseBuilder().PrinterGroup().Text(0x41, "printer-info", "x").Build().ToList();
        bytes.RemoveAt(bytes.Count - 2);   // drop a value byte; the declared length now overruns

        Assert.Throws<FormatException>(() => Ipp.Parse([.. bytes]));
    }

    [Fact]
    public void A_response_that_is_absurdly_large_or_deeply_nested_is_refused()
    {
        Assert.Throws<FormatException>(() => Ipp.Parse(new byte[Ipp.MaxBytes + 1]));
        var nested = new List<byte> { 1, 1, 0, 0, 0, 0, 0, 1, 0x04, 0x34, 0, 1, (byte)'x', 0, 0 };
        for (var i = 0; i < 200; i++)
            nested.AddRange([0x34, 0, 0, 0, 0]);
        nested.Add(0x03);
        Assert.Throws<FormatException>(() => Ipp.Parse([.. nested]));
    }
}
