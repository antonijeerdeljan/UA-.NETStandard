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
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using Microsoft.Extensions.Compliance.Classification;
using Microsoft.Extensions.Compliance.Redaction;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using Opc.Ua.Bindings;
using Opc.Ua.Tests;

namespace Opc.Ua.Core.Tests.Stack.Tcp
{
    /// <summary>
    /// End to end check of the network address classification on a refused
    /// connect: the default output still contains the address, and with
    /// redaction enabled no entry carries it.
    /// </summary>
    [TestFixture]
    [Category("Diagnostics")]
    [NonParallelizable]
    public class ClassifiedConnectLogTests
    {
        private static readonly int[] s_eventIds =
        [
            CoreEventIds.UaSCBinaryClientChannel + 1,
            CoreEventIds.UaSCBinaryClientChannel + 3,
            CoreEventIds.TcpByteTransport + 0
        ];

        [Test]
        public void RefusedConnectLogsAddressByDefault()
        {
            using var recorder = new RecordingLoggerProvider();
            using var factory = LoggerFactory.Create(b => b
                .AddProvider(recorder)
                .SetMinimumLevel(LogLevel.Trace));

            int port = ConnectRefused(new TestTelemetryContext(factory));

            Dictionary<int, RecordedLogRecord> records = Relevant(recorder);
            string address = "127.0.0.1:" + port;
            Assert.That(
                records[CoreEventIds.UaSCBinaryClientChannel + 1].Message,
                Does.StartWith("CLIENTCHANNEL SOCKET CONNECTING to opc.tcp://" + address + "/"));
            Assert.That(
                records[CoreEventIds.UaSCBinaryClientChannel + 3].Message,
                Does.StartWith("CLIENTCHANNEL CONNECT FAILED via opc.tcp://" + address + "/"));
            Assert.That(
                records[CoreEventIds.TcpByteTransport + 0].Message,
                Is.EqualTo("Failed to connect socket to " + address + "."));
            Assert.That(
                records[CoreEventIds.UaSCBinaryClientChannel + 1].Properties["Url"]?.ToString(),
                Does.Contain(address));
            Assert.That(records[CoreEventIds.TcpByteTransport + 0].Properties["IdnHost"], Is.EqualTo("127.0.0.1"));
            Assert.That(records[CoreEventIds.TcpByteTransport + 0].Properties["Port"], Is.EqualTo(port));
        }

        [Test]
        public void RefusedConnectLogsNoAddressWithRedaction()
        {
            using var recorder = new RecordingLoggerProvider(formatValues: true);
            var services = new ServiceCollection();
            services.AddLogging(b => b
                .AddProvider(recorder)
                .SetMinimumLevel(LogLevel.Trace)
                .EnableRedaction());
            services.AddRedaction(r => r.SetRedactor<ErasingRedactor>(
                new DataClassificationSet(OpcUaDataClasses.NetworkAddress)));
            using ServiceProvider provider = services.BuildServiceProvider();

            int port = ConnectRefused(
                new TestTelemetryContext(provider.GetRequiredService<ILoggerFactory>()));

            Dictionary<int, RecordedLogRecord> records = Relevant(recorder);
            Assert.That(
                records[CoreEventIds.TcpByteTransport + 0].Message,
                Is.EqualTo("Failed to connect socket to :."));
            string portText = port.ToString(System.Globalization.CultureInfo.InvariantCulture);
            foreach (RecordedLogRecord record in recorder.Records)
            {
                Assert.That(record.Message, Does.Not.Contain("127.0.0.1"), record.Message);
                Assert.That(record.Message, Does.Not.Contain(":" + portText), record.Message);
                foreach (KeyValuePair<string, object?> property in record.Properties)
                {
                    if (property.Key == "{OriginalFormat}")
                    {
                        continue;
                    }
                    string value = property.Value?.ToString() ?? string.Empty;
                    Assert.That(value, Does.Not.Contain("127.0.0.1"), property.Key);
                    Assert.That(value, Does.Not.Contain(portText), property.Key);
                }
            }
        }

        private static Dictionary<int, RecordedLogRecord> Relevant(RecordingLoggerProvider recorder)
        {
            var records = recorder.Records
                .Where(r => s_eventIds.Contains(r.EventId.Id))
                .GroupBy(r => r.EventId.Id)
                .ToDictionary(g => g.Key, g => g.First());
            Assert.That(records.Keys, Is.EquivalentTo(s_eventIds));
            return records;
        }

        /// <summary>
        /// Connect to a loopback port that is bound but not listening, so the
        /// connect is refused.
        /// </summary>
        private static int ConnectRefused(ITelemetryContext telemetry)
        {
            using var socket = new Socket(
                AddressFamily.InterNetwork,
                SocketType.Stream,
                ProtocolType.Tcp);
            socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            int port = ((IPEndPoint)socket.LocalEndPoint!).Port;
            var url = new Uri("opc.tcp://127.0.0.1:" + port + "/refused");

            using var channel = new UaSCUaBinaryTransportChannel(
                new TcpByteTransportFactory(telemetry),
                telemetry)
            {
                OperationTimeout = 5000
            };
            var settings = new TransportChannelSettings
            {
                Description = new EndpointDescription
                {
                    EndpointUrl = url.ToString(),
                    SecurityMode = MessageSecurityMode.None,
                    SecurityPolicyUri = SecurityPolicies.None,
                    TransportProfileUri = Profiles.UaTcpTransport
                },
                Configuration = EndpointConfiguration.Create(),
                NamespaceUris = new NamespaceTable(),
                Factory = EncodeableFactory.Create()
            };
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            ServiceResultException? sre = Assert.ThrowsAsync<ServiceResultException>(
                async () => await channel.OpenAsync(url, settings, cts.Token).ConfigureAwait(false));
            Assert.That(sre!.StatusCode, Is.EqualTo(StatusCodes.BadNotConnected));
            return port;
        }

        private sealed class TestTelemetryContext : TelemetryContextBase
        {
            public TestTelemetryContext(ILoggerFactory loggerFactory)
                : base(loggerFactory)
            {
            }
        }
    }
}
