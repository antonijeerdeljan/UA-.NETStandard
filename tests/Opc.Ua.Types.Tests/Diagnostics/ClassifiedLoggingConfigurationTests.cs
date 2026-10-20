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
using System.Linq;
using Microsoft.Extensions.Compliance.Classification;
using Microsoft.Extensions.Compliance.Redaction;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using Opc.Ua.Tests;

namespace Opc.Ua.Types.Tests.Diagnostics
{
    /// <summary>
    /// Runs one classified message through the logging configurations an
    /// application can choose and pins the resulting text and structured
    /// values of each.
    /// </summary>
    [TestFixture]
    [Category("Diagnostics")]
    [Parallelizable]
    public class ClassifiedLoggingConfigurationTests
    {
        private const string kUrl = "opc.tcp://10.1.2.3:4840/plant";
        private const int kPort = 4840;
        private const string kAppUri = "urn:plant-host:Line1";
        private const string kUser = "operator7";
        private const string kRaw =
            "Connecting to opc.tcp://10.1.2.3:4840/plant on port 4840 for " +
            "urn:plant-host:Line1 as operator7 (3 tries).";

        /// <summary>
        /// The configurations under test.
        /// </summary>
        public enum Configuration
        {
            /// <summary>LoggerFactory.Create, nothing else.</summary>
            PlainFactory,
            /// <summary>AddLogging without redaction.</summary>
            DependencyInjection,
            /// <summary>EnableRedaction without any redactor registered.</summary>
            RedactionWithoutRedactors,
            /// <summary>Erase network addresses, other classes fall back to
            /// the default (erasing) fallback redactor.</summary>
            EraseAddressesDefaultFallback,
            /// <summary>Erase network addresses, keep the other classes.</summary>
            EraseAddressesOnly,
            /// <summary>As <see cref="EraseAddressesOnly"/> but with the
            /// default discriminator.</summary>
            EraseAddressesOnlyWithDiscriminator,
            /// <summary>Erase all three classes explicitly.</summary>
            EraseAllClasses,
            /// <summary>Hash network addresses with the HMAC redactor.</summary>
            HmacAddresses
        }

        [TestCase(Configuration.PlainFactory, kRaw)]
        [TestCase(Configuration.DependencyInjection, kRaw)]
        [TestCase(
            Configuration.EraseAddressesDefaultFallback,
            "Connecting to  on port  for  as  (3 tries).")]
        [TestCase(
            Configuration.EraseAddressesOnly,
            "Connecting to  on port  for urn:plant-host:Line1 as operator7 (3 tries).")]
        [TestCase(
            Configuration.EraseAddressesOnlyWithDiscriminator,
            "Connecting to  on port  for urn:plant-host:Line1:AppUri as operator7:User (3 tries).")]
        [TestCase(
            Configuration.EraseAllClasses,
            "Connecting to  on port  for  as  (3 tries).")]
        public void ConfigurationProducesExpectedText(Configuration configuration, string expected)
        {
            using var recorder = new RecordingLoggerProvider(formatValues: true);
            using Pipeline pipeline = Pipeline.Create(configuration, recorder);

            pipeline.Logger.Connecting(kUrl, kPort, kAppUri, kUser, 3);

            RecordedLogRecord record = recorder.Records.Single();
            Assert.That(record.Message, Is.EqualTo(expected));
            Assert.That(record.EventId.Id, Is.EqualTo(1));
            Assert.That(record.LogLevel, Is.EqualTo(LogLevel.Warning));
            // The unclassified value is never touched.
            Assert.That(record.Properties["Count"], Is.EqualTo("3"));
            Assert.That(
                record.Properties["{OriginalFormat}"],
                Is.EqualTo("Connecting to {Url} on port {Port} for {AppUri} as {User} ({Count} tries)."));
            bool addressesHidden = expected != kRaw;
            if (addressesHidden)
            {
                AssertNoValue(record, kUrl, "10.1.2.3", "4840");
            }
            else
            {
                Assert.That(record.Properties["Url"], Is.EqualTo(kUrl));
                Assert.That(record.Properties["Port"], Is.EqualTo("4840"));
                Assert.That(record.Properties["AppUri"], Is.EqualTo(kAppUri));
                Assert.That(record.Properties["User"], Is.EqualTo(kUser));
            }
        }

        [Test]
        public void RedactionWithoutRedactorsAppendsTheTagName()
        {
            // Microsoft.Extensions.Telemetry behaviour, pinned so a change is
            // noticed: EnableRedaction without a redactor for the class uses a
            // pass-through redactor, and the default discriminator appends
            // ":<TagName>" to every classified value. Applications that enable
            // redaction should register redactors (or turn the discriminator
            // off), see docs/Diagnostics.md.
            using var recorder = new RecordingLoggerProvider(formatValues: true);
            using Pipeline pipeline = Pipeline.Create(Configuration.RedactionWithoutRedactors, recorder);

            pipeline.Logger.Connecting(kUrl, kPort, kAppUri, kUser, 3);

            RecordedLogRecord record = recorder.Records.Single();
            Assert.That(
                record.Message,
                Is.EqualTo(
                    "Connecting to opc.tcp://10.1.2.3:4840/plant:Url on port 4840:Port for " +
                    "urn:plant-host:Line1:AppUri as operator7:User (3 tries)."));
            Assert.That(record.Properties["Url"], Is.EqualTo(kUrl + ":Url"));
        }

        [Test]
        public void HmacHidesAddressesButKeepsThemCorrelatable()
        {
            using var recorder = new RecordingLoggerProvider(formatValues: true);
            using Pipeline pipeline = Pipeline.Create(Configuration.HmacAddresses, recorder);

            pipeline.Logger.Connecting(kUrl, kPort, kAppUri, kUser, 1);
            pipeline.Logger.Connecting(kUrl, kPort, kAppUri, kUser, 2);
            pipeline.Logger.Connecting("opc.tcp://10.9.9.9:4840/other", kPort, kAppUri, kUser, 3);

            IReadOnlyList<RecordedLogRecord> records = recorder.Records;
            Assert.That(records, Has.Count.EqualTo(3));
            foreach (RecordedLogRecord record in records)
            {
                AssertNoValue(record, kUrl, "10.1.2.3", "10.9.9.9", "4840");
                Assert.That(record.Properties["Url"], Is.Not.Empty);
                Assert.That(record.Properties["AppUri"], Is.EqualTo(kAppUri));
            }
            // Same address, same hash; different address, different hash.
            Assert.That(records[0].Properties["Url"], Is.EqualTo(records[1].Properties["Url"]));
            Assert.That(records[0].Properties["Url"], Is.Not.EqualTo(records[2].Properties["Url"]));
        }

        [TestCase(Configuration.PlainFactory)]
        [TestCase(Configuration.EraseAddressesOnly)]
        [TestCase(Configuration.HmacAddresses)]
        public void RestrictedLogGetsRawAddressesForEveryGeneralConfiguration(
            Configuration general)
        {
            using var generalRecorder = new RecordingLoggerProvider(formatValues: true);
            using var restrictedRecorder = new RecordingLoggerProvider(formatValues: true);
            using Pipeline pipeline = Pipeline.Create(general, generalRecorder);
            using var restricted = LoggerFactory.Create(b => b.AddProvider(restrictedRecorder));
            using var factory = new RestrictedDataLoggerFactory(
                pipeline.Factory,
                restricted,
                OpcUaDataClasses.NetworkAddress);
            ILogger logger = new TestTelemetryContext(factory)
                .CreateClassifiedLogger<ClassifiedLoggingConfigurationTests>();

            logger.Connecting(kUrl, kPort, kAppUri, kUser, 3);
            logger.Unclassified(7);
            logger.IdentityOnly(kUser);

            Assert.That(generalRecorder.Records, Has.Count.EqualTo(3));
            Assert.That(restrictedRecorder.Records, Has.Count.EqualTo(1));
            RecordedLogRecord restrictedRecord = restrictedRecorder.Records[0];
            Assert.That(restrictedRecord.Message, Is.EqualTo(kRaw));
            Assert.That(restrictedRecord.Properties["Url"], Is.EqualTo(kUrl));
            Assert.That(restrictedRecord.Properties["Port"], Is.EqualTo("4840"));
            if (general != Configuration.PlainFactory)
            {
                AssertNoValue(generalRecorder.Records[0], kUrl, "10.1.2.3", "4840");
            }
        }

        private static void AssertNoValue(RecordedLogRecord record, params string[] values)
        {
            foreach (string value in values)
            {
                Assert.That(record.Message, Does.Not.Contain(value), record.Message);
                foreach (KeyValuePair<string, object?> property in record.Properties)
                {
                    if (property.Key == "{OriginalFormat}")
                    {
                        continue;
                    }
                    Assert.That(
                        Convert.ToString(property.Value, CultureInfo.InvariantCulture),
                        Does.Not.Contain(value),
                        property.Key);
                }
            }
        }

        /// <summary>
        /// A logging pipeline for one configuration, with the logger the
        /// stack would create from it through the telemetry context.
        /// </summary>
        private sealed class Pipeline : IDisposable
        {
            private Pipeline(ILoggerFactory factory, IDisposable owner)
            {
                Factory = factory;
                m_owner = owner;
                Logger = new TestTelemetryContext(factory)
                    .CreateClassifiedLogger<ClassifiedLoggingConfigurationTests>();
            }

            public ILoggerFactory Factory { get; }

            public ILogger Logger { get; }

            public static Pipeline Create(Configuration configuration, RecordingLoggerProvider recorder)
            {
                if (configuration == Configuration.PlainFactory)
                {
                    ILoggerFactory plain = LoggerFactory.Create(b => b.AddProvider(recorder));
                    return new Pipeline(plain, plain);
                }
                var services = new ServiceCollection();
                services.AddLogging(b =>
                {
                    b.AddProvider(recorder);
                    if (configuration != Configuration.DependencyInjection)
                    {
                        b.EnableRedaction();
                    }
                });
                switch (configuration)
                {
                    case Configuration.EraseAddressesDefaultFallback:
                        services.AddRedaction(r => r.SetRedactor<ErasingRedactor>(
                            new DataClassificationSet(OpcUaDataClasses.NetworkAddress)));
                        break;
                    case Configuration.EraseAddressesOnly:
                    case Configuration.EraseAddressesOnlyWithDiscriminator:
                        services.AddRedaction(r => r
                            .SetRedactor<ErasingRedactor>(
                                new DataClassificationSet(OpcUaDataClasses.NetworkAddress))
                            .SetFallbackRedactor<NullRedactor>());
                        if (configuration == Configuration.EraseAddressesOnly)
                        {
                            services.Configure<LoggerRedactionOptions>(
                                o => o.ApplyDiscriminator = false);
                        }
                        break;
                    case Configuration.EraseAllClasses:
                        services.AddRedaction(r => r
                            .SetRedactor<ErasingRedactor>(
                                new DataClassificationSet(OpcUaDataClasses.NetworkAddress),
                                new DataClassificationSet(OpcUaDataClasses.ApplicationUri),
                                new DataClassificationSet(OpcUaDataClasses.UserIdentity))
                            .SetFallbackRedactor<NullRedactor>());
                        break;
                    case Configuration.HmacAddresses:
#pragma warning disable EXTEXP0002 // HMAC redaction is experimental in Compliance.Redaction
                        services.AddRedaction(r => r
                            .SetHmacRedactor(
                                o =>
                                {
                                    o.Key = Convert.ToBase64String(
                                        Enumerable.Range(0, 64).Select(i => (byte)i).ToArray());
                                    o.KeyId = 1;
                                },
                                new DataClassificationSet(OpcUaDataClasses.NetworkAddress))
                            .SetFallbackRedactor<NullRedactor>());
#pragma warning restore EXTEXP0002
                        services.Configure<LoggerRedactionOptions>(o => o.ApplyDiscriminator = false);
                        break;
                }
                ServiceProvider provider = services.BuildServiceProvider();
                return new Pipeline(provider.GetRequiredService<ILoggerFactory>(), provider);
            }

            public void Dispose()
            {
                m_owner.Dispose();
            }

            private readonly IDisposable m_owner;
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
