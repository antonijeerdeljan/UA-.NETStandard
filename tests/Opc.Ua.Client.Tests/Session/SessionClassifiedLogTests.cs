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

// The tests log constant values; the analyzer's concern (argument cost when
// logging is disabled) does not apply.
#pragma warning disable CA1873

using System;
using System.Collections.Generic;
using System.Globalization;
using Microsoft.Extensions.Compliance.Classification;
using Microsoft.Extensions.Compliance.Redaction;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using Opc.Ua.Tests;

namespace Opc.Ua.Client.Tests
{
    /// <summary>
    /// The keep alive messages of the session classify the endpoint URL:
    /// unchanged by default, removed when network addresses are redacted.
    /// </summary>
    [TestFixture]
    [Category("Logging")]
    [Parallelizable]
    public sealed class SessionClassifiedLogTests
    {
        private const string kEndpointUrl = "opc.tcp://10.1.2.3:4840/plant";
        private const string kReadFailedTemplate =
            "Keep alive read failed: {ServiceResult}, EndpointUrl={EndpointUrl}," +
            " RequestCount={Good}/{Outstanding}, SessionId={SessionId}";
        private const string kLateTemplate =
            "KEEP ALIVE LATE: {Duration}ms, EndpointUrl={EndpointUrl}," +
            " RequestCount={Good}/{Outstanding}, SessionId={SessionId}";

        [Test]
        public void KeepAliveMessagesAreUnchangedByDefault()
        {
            using var recorder = new RecordingLoggerProvider();
            using var factory = LoggerFactory.Create(b => b.AddProvider(recorder));
            ILogger logger = new TestTelemetryContext(factory).CreateClassifiedLogger<SessionClassifiedLogTests>();
            ILogger reference = factory.CreateLogger("Reference");
            var result = new ServiceResult(StatusCodes.BadTimeout);
            var sessionId = new NodeId(42u, 1);

            logger.KeepAliveReadFailedServiceResultEndpointUrl(result, kEndpointUrl, 1, 2, sessionId);
            s_readFailed(reference, result, kEndpointUrl, 1, 2, sessionId, null);
            logger.KEEPALIVELATEDurationMsEndpointUrl(1500.5, kEndpointUrl, 3, 4, sessionId);
            s_late(reference, 1500.5, kEndpointUrl, 3, 4, sessionId, null);

            IReadOnlyList<RecordedLogRecord> records = recorder.Records;
            Assert.That(records, Has.Count.EqualTo(4));
            Assert.That(records[0].EventId.Id, Is.EqualTo(ClientEventIds.Session + 54));
            Assert.That(records[2].EventId.Id, Is.EqualTo(ClientEventIds.Session + 57));
            Assert.That(records[0].Message, Is.EqualTo(records[1].Message));
            Assert.That(records[2].Message, Is.EqualTo(records[3].Message));
            Assert.That(records[0].Message, Does.Contain("EndpointUrl=" + kEndpointUrl + ","));
            Assert.That(records[2].Message, Does.Contain("EndpointUrl=" + kEndpointUrl + ","));
            Assert.That(records[0].Properties["EndpointUrl"], Is.EqualTo(kEndpointUrl));
            Assert.That(records[2].Properties["EndpointUrl"], Is.EqualTo(kEndpointUrl));
        }

        [Test]
        public void KeepAliveMessagesDropTheEndpointWithRedaction()
        {
            using var recorder = new RecordingLoggerProvider(formatValues: true);
            var services = new ServiceCollection();
            services.AddLogging(b => b.AddProvider(recorder).EnableRedaction());
            services.AddRedaction(r => r.SetRedactor<ErasingRedactor>(
                new DataClassificationSet(OpcUaDataClasses.NetworkAddress)));
            using ServiceProvider provider = services.BuildServiceProvider();
            ILogger logger = new TestTelemetryContext(provider.GetRequiredService<ILoggerFactory>())
                .CreateClassifiedLogger<SessionClassifiedLogTests>();
            var sessionId = new NodeId(42u, 1);

            logger.KeepAliveReadFailedServiceResultEndpointUrl(
                new ServiceResult(StatusCodes.BadTimeout), kEndpointUrl, 1, 2, sessionId);
            logger.KEEPALIVELATEDurationMsEndpointUrl(1500.5, kEndpointUrl, 3, 4, sessionId);

            IReadOnlyList<RecordedLogRecord> records = recorder.Records;
            Assert.That(records, Has.Count.EqualTo(2));
            foreach (RecordedLogRecord record in records)
            {
                Assert.That(record.Message, Does.Contain("EndpointUrl=,"));
                Assert.That(record.Message, Does.Not.Contain("10.1.2.3"));
                Assert.That(record.Properties["EndpointUrl"], Is.Empty);
                Assert.That(record.Properties["SessionId"], Is.EqualTo(
                    Convert.ToString(sessionId, CultureInfo.InvariantCulture)));
            }
        }

        private static readonly Action<ILogger, ServiceResult, string?, int, int, NodeId?, Exception?> s_readFailed =
            LoggerMessage.Define<ServiceResult, string?, int, int, NodeId?>(
                LogLevel.Error,
                new EventId(ClientEventIds.Session + 54),
                kReadFailedTemplate);

        private static readonly Action<ILogger, double, string?, int, int, NodeId?, Exception?> s_late =
            LoggerMessage.Define<double, string?, int, int, NodeId?>(
                LogLevel.Information,
                new EventId(ClientEventIds.Session + 57),
                kLateTemplate);

        private sealed class TestTelemetryContext : TelemetryContextBase
        {
            public TestTelemetryContext(ILoggerFactory loggerFactory)
                : base(loggerFactory)
            {
            }
        }
    }
}
