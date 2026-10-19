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
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using Opc.Ua.Bindings;
using Opc.Ua.Tests;

namespace Opc.Ua.Core.Tests.Stack.Transport
{
    /// <summary>
    /// End-to-end tests of the sensitive data log split for a failed
    /// connect, where the stack wraps the socket error and the address is
    /// only in the message of the inner exception.
    /// </summary>
    [TestFixture]
    [Category("TcpTransport")]
    [SetCulture("en-us")]
    [SetUICulture("en-us")]
    [NonParallelizable]
    public sealed class SensitiveDataLoggingTests
    {
        private const string kSensitivePrefix = SensitiveDataLoggerOptions.DefaultSensitiveCategoryPrefix;
        private const int kConnectFailedId = CoreEventIds.UaSCBinaryClientChannel + 3;
        private const int kConnectingId = CoreEventIds.UaSCBinaryClientChannel + 1;
        private const int kSocketConnectFailedId = CoreEventIds.TcpByteTransport + 0;

        [Test]
        [CancelAfter(15000)]
        public async Task ConnectFailureLogsAddressesWithoutWrapperAsync()
        {
            var provider = new RecordingLoggerProvider();
            using ILoggerFactory factory = CreateFactory(provider);

            (Uri url, int port) = await ConnectToRefusedPortAsync(factory).ConfigureAwait(false);

            RecordedLogRecord[] records = [.. provider.Records];
            Assert.That(records.Any(r => r.CategoryName.StartsWith(kSensitivePrefix, StringComparison.Ordinal)), Is.False);
            RecordedLogRecord connectFailed = records.Single(r => r.EventId.Id == kConnectFailedId);
            Assert.That(connectFailed.LogLevel, Is.EqualTo(LogLevel.Error));
            Assert.That(connectFailed.Message, Does.StartWith($"CLIENTCHANNEL CONNECT FAILED via {url}: "));
            Assert.That(connectFailed.Exception, Is.InstanceOf<SocketException>());
            Assert.That(
                records.Single(r => r.EventId.Id == kSocketConnectFailedId).Message,
                Is.EqualTo($"Failed to connect socket to 127.0.0.1:{port}."));
        }

        [Test]
        [CancelAfter(15000)]
        public async Task ConnectFailureIsSplitWithWrapperAsync()
        {
            var provider = new RecordingLoggerProvider();
            using var factory = new SensitiveDataLoggerFactory(CreateFactory(provider));

            (Uri url, int port) = await ConnectToRefusedPortAsync(factory).ConfigureAwait(false);

            RecordedLogRecord[] records = [.. provider.Records];
            RecordedLogRecord[] normal = [.. records.Where(r => !r.CategoryName.StartsWith(kSensitivePrefix, StringComparison.Ordinal))];
            RecordedLogRecord[] sensitive = [.. records.Where(r => r.CategoryName.StartsWith(kSensitivePrefix, StringComparison.Ordinal))];
            Assert.That(normal, Is.Not.Empty);

            // No entry of the normal categories leaks the address, port or url.
            string portText = ":" + port.ToString(CultureInfo.InvariantCulture);
            foreach (RecordedLogRecord record in normal)
            {
                foreach (string text in GetTexts(record))
                {
                    Assert.That(text, Does.Not.Contain("127.0.0.1"), $"{record.CategoryName} {record.EventId}");
                    Assert.That(text, Does.Not.Contain(portText), $"{record.CategoryName} {record.EventId}");
                }
            }

            foreach (int eventId in new[] { kConnectingId, kSocketConnectFailedId, kConnectFailedId })
            {
                RecordedLogRecord redacted = normal.Single(r => r.EventId.Id == eventId);
                RecordedLogRecord complete = sensitive.Single(r => r.EventId.Id == eventId);
                Assert.That(complete.CategoryName, Is.EqualTo(kSensitivePrefix + redacted.CategoryName));
                Assert.That(complete.LogLevel, Is.EqualTo(redacted.LogLevel));
                Assert.That(complete.EventId, Is.EqualTo(redacted.EventId));
                Assert.That(complete.Message, Does.Contain("127.0.0.1"));
            }

            RecordedLogRecord connectFailed = normal.Single(r => r.EventId.Id == kConnectFailedId);
            Assert.That(connectFailed.LogLevel, Is.EqualTo(LogLevel.Error));
            // The transport has no remote endpoint after a refused connect;
            // null values are not sensitive and format as before.
            Assert.That(connectFailed.Message, Does.StartWith("CLIENTCHANNEL CONNECT FAILED via [redacted]: (null), ChannelId="));
            var exception = (SensitiveDataRedactedException)connectFailed.Exception!;
            Assert.That(exception.OriginalTypeName, Is.EqualTo(typeof(SocketException).FullName));
            Assert.That(exception.Message, Is.EqualTo("[redacted] (ConnectionRefused)"));
            Assert.That(exception.StackTrace, Is.Not.Empty);

            RecordedLogRecord connectFailedComplete = sensitive.Single(r => r.EventId.Id == kConnectFailedId);
            Assert.That(connectFailedComplete.Message, Does.StartWith($"CLIENTCHANNEL CONNECT FAILED via {url}: "));
            Assert.That(connectFailedComplete.Exception, Is.InstanceOf<SocketException>());
            Assert.That(
                sensitive.Single(r => r.EventId.Id == kSocketConnectFailedId).Message,
                Is.EqualTo($"Failed to connect socket to 127.0.0.1:{port}."));
        }

        private static IEnumerable<string> GetTexts(RecordedLogRecord record)
        {
            yield return record.Message;
            foreach (KeyValuePair<string, object?> value in record.Properties)
            {
                yield return Convert.ToString(value.Value, CultureInfo.InvariantCulture) ?? string.Empty;
            }
            if (record.Exception != null)
            {
                yield return record.Exception.ToString();
            }
        }

        private static ILoggerFactory CreateFactory(RecordingLoggerProvider provider)
        {
            return LoggerFactory.Create(builder => builder
                .SetMinimumLevel(LogLevel.Trace)
                .AddProvider(provider));
        }

        /// <summary>
        /// Open a channel to a bound port without a listener, so the
        /// connect is refused.
        /// </summary>
        private static async Task<(Uri Url, int Port)> ConnectToRefusedPortAsync(ILoggerFactory loggerFactory)
        {
            using var reserved = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            reserved.Bind(new IPEndPoint(IPAddress.Loopback, 0));
            int port = ((IPEndPoint)reserved.LocalEndPoint!).Port;
            var url = new Uri($"opc.tcp://127.0.0.1:{port}");

            var telemetry = new TestTelemetryContext(loggerFactory);
            EndpointConfiguration configuration = EndpointConfiguration.Create();
            configuration.OperationTimeout = 5000;
            using var channel = new UaSCUaBinaryTransportChannel(new TcpByteTransportFactory(telemetry), telemetry)
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
                Configuration = configuration,
                NamespaceUris = new NamespaceTable(),
                Factory = EncodeableFactory.Create()
            };

            ServiceResultException? error = null;
            try
            {
                await channel.OpenAsync(url, settings, CancellationToken.None).ConfigureAwait(false);
            }
            catch (ServiceResultException e)
            {
                error = e;
            }
            Assert.That(error, Is.Not.Null);
            Assert.That(error!.StatusCode, Is.EqualTo((StatusCode)StatusCodes.BadNotConnected));
            Assert.That(error.InnerException, Is.InstanceOf<SocketException>());
            return (url, port);
        }

        private sealed class TestTelemetryContext(ILoggerFactory loggerFactory)
            : TelemetryContextBase(loggerFactory);
    }
}
