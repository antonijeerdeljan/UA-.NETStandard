/* ========================================================================
 * Copyright (c) 2005-2025 The OPC Foundation, Inc. All rights reserved.
 *
 * OPC Foundation MIT License 1.00
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * The complete license agreement can be found here:
 * http://opcfoundation.org/License/MIT/1.00/
 * ======================================================================*/

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using Opc.Ua.Tests;

// The tests log unconditionally to assert on the recorded entries.
#pragma warning disable CA1873

namespace Opc.Ua.Client.Tests
{
    /// <summary>
    /// Tests the sensitive data log split for the keep alive messages of
    /// <see cref="Session"/>. Opc.Ua.Client uses the extended logging source
    /// generator of Microsoft.Extensions.Telemetry.Abstractions, so this
    /// also proves that <see cref="SensitiveValue"/> reaches the logger
    /// unformatted with that generator.
    /// </summary>
    [TestFixture]
    [SetCulture("en-us")]
    [Parallelizable]
    public sealed class SessionSensitiveLoggingTests
    {
        private const string kCategory = "Opc.Ua.Client.Session";
        private const string kSensitiveCategory = "Sensitive." + kCategory;
        private const string kEndpointUrl = "opc.tcp://10.1.2.3:4840/plant";
        private const string kAddress = "10.1.2.3";

        [Test]
        public void KeepAliveFailedLogsAddressesWithoutWrapper()
        {
            var provider = new RecordingLoggerProvider();
            using ILoggerFactory factory = CreateFactory(provider);
            ServiceResult error = CreateErrorWithAddress();

            factory.CreateLogger(kCategory).KeepAliveReadFailedServiceResultEndpointUrl(
                SensitiveValue.FromServiceResult(error),
                SensitiveValue.Create(kEndpointUrl),
                1,
                2,
                null);

            RecordedLogRecord record = provider.Records.Single();
            Assert.That(record.CategoryName, Is.EqualTo(kCategory));
            Assert.That(record.Message, Does.StartWith(
                $"Keep alive read failed: {error}, EndpointUrl={kEndpointUrl}, RequestCount=1/2, SessionId="));
            Assert.That(record.Properties["EndpointUrl"]?.ToString(), Is.EqualTo(kEndpointUrl));
            Assert.That(record.Properties["ServiceResult"]?.ToString(), Is.EqualTo(error.ToString()));
        }

        [Test]
        public void KeepAliveFailedIsSplitWithWrapper()
        {
            var provider = new RecordingLoggerProvider();
            using var factory = new SensitiveDataLoggerFactory(CreateFactory(provider));
            ServiceResult error = CreateErrorWithAddress();

            factory.CreateLogger(kCategory).KeepAliveReadFailedServiceResultEndpointUrl(
                SensitiveValue.FromServiceResult(error),
                SensitiveValue.Create(kEndpointUrl),
                1,
                2,
                null);

            RecordedLogRecord normal = provider.Records.Single(r => r.CategoryName == kCategory);
            RecordedLogRecord sensitive = provider.Records.Single(r => r.CategoryName == kSensitiveCategory);

            AssertNoAddress(normal);
            Assert.That(normal.Message, Does.StartWith(
                "Keep alive read failed: BadNotConnected, EndpointUrl=[redacted], RequestCount=1/2, SessionId="));
            Assert.That(normal.Properties["ServiceResult"], Is.EqualTo("BadNotConnected"));
            Assert.That(normal.Properties["EndpointUrl"], Is.EqualTo("[redacted]"));
            Assert.That(normal.LogLevel, Is.EqualTo(LogLevel.Error));
            Assert.That(normal.EventId.Id, Is.EqualTo(ClientEventIds.Session + 54));

            Assert.That(sensitive.LogLevel, Is.EqualTo(normal.LogLevel));
            Assert.That(sensitive.EventId, Is.EqualTo(normal.EventId));
            Assert.That(sensitive.Message, Does.StartWith(
                $"Keep alive read failed: {error}, EndpointUrl={kEndpointUrl}, RequestCount=1/2, SessionId="));
        }

        [Test]
        public void KeepAliveLateIsSplitWithWrapper()
        {
            var provider = new RecordingLoggerProvider();
            using var factory = new SensitiveDataLoggerFactory(CreateFactory(provider));

            factory.CreateLogger(kCategory).KEEPALIVELATEDurationMsEndpointUrl(
                12.5,
                SensitiveValue.Create(kEndpointUrl),
                1,
                2,
                null);

            RecordedLogRecord normal = provider.Records.Single(r => r.CategoryName == kCategory);
            RecordedLogRecord sensitive = provider.Records.Single(r => r.CategoryName == kSensitiveCategory);
            AssertNoAddress(normal);
            Assert.That(normal.Message, Does.StartWith(
                "KEEP ALIVE LATE: 12.5ms, EndpointUrl=[redacted], RequestCount=1/2, SessionId="));
            Assert.That(normal.LogLevel, Is.EqualTo(LogLevel.Information));
            Assert.That(normal.EventId.Id, Is.EqualTo(ClientEventIds.Session + 57));
            Assert.That(sensitive.EventId, Is.EqualTo(normal.EventId));
            Assert.That(sensitive.Message, Does.StartWith(
                $"KEEP ALIVE LATE: 12.5ms, EndpointUrl={kEndpointUrl}, RequestCount=1/2, SessionId="));
        }

        [Test]
        public void MissingEndpointUrlFormatsAsBefore()
        {
            var provider = new RecordingLoggerProvider();
            using var factory = new SensitiveDataLoggerFactory(CreateFactory(provider));

            factory.CreateLogger(kCategory).KEEPALIVELATEDurationMsEndpointUrl(
                12.5,
                SensitiveValue.Create(null),
                1,
                2,
                null);

            // A null value is not sensitive: one entry, formatted like a
            // null string argument.
            RecordedLogRecord record = provider.Records.Single();
            Assert.That(record.CategoryName, Is.EqualTo(kCategory));
            Assert.That(record.Message, Does.StartWith("KEEP ALIVE LATE: 12.5ms, EndpointUrl=(null), RequestCount=1/2"));
        }

        private static ILoggerFactory CreateFactory(RecordingLoggerProvider provider)
        {
            return LoggerFactory.Create(builder => builder
                .SetMinimumLevel(LogLevel.Trace)
                .AddProvider(provider));
        }

        private static ServiceResult CreateErrorWithAddress()
        {
            var error = new ServiceResult(
                StatusCodes.BadNotConnected,
                new LocalizedText("Could not connect to " + kAddress + ":4840"));
            Assert.That(error.ToString(), Does.Contain(kAddress));
            return error;
        }

        private static void AssertNoAddress(RecordedLogRecord record)
        {
            Assert.That(record.Message, Does.Not.Contain(kAddress));
            foreach (KeyValuePair<string, object?> value in record.Properties)
            {
                Assert.That(
                    Convert.ToString(value.Value, CultureInfo.InvariantCulture),
                    Does.Not.Contain(kAddress),
                    value.Key);
            }
        }
    }
}
