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
    /// Tests for the data classification of log values
    /// (<see cref="OpcUaDataClasses"/>, <see cref="ClassifiedLogging"/>
    /// and <see cref="RestrictedDataLoggerFactory"/>).
    /// </summary>
    [TestFixture]
    [Category("Diagnostics")]
    [Parallelizable]
    public class ClassifiedLoggingTests
    {
        private const string kUrl = "opc.tcp://10.1.2.3:4840/plant";
        private const int kPort = 4840;
        private const string kAppUri = "urn:plant-host:Line1";
        private const string kUser = "operator7";
        private const string kTemplate =
            "Connecting to {Url} on port {Port} for {AppUri} as {User} ({Count} tries).";

        [Test]
        public void TaxonomyHasTheDocumentedClasses()
        {
            Assert.That(OpcUaDataClasses.TaxonomyName, Is.EqualTo("OpcUa"));
            Assert.That(
                OpcUaDataClasses.NetworkAddress,
                Is.EqualTo(new DataClassification("OpcUa", "NetworkAddress")));
            Assert.That(
                OpcUaDataClasses.ApplicationUri,
                Is.EqualTo(new DataClassification("OpcUa", "ApplicationUri")));
            Assert.That(
                OpcUaDataClasses.UserIdentity,
                Is.EqualTo(new DataClassification("OpcUa", "UserIdentity")));
            Assert.That(
                new NetworkAddressAttribute().Classification,
                Is.EqualTo(OpcUaDataClasses.NetworkAddress));
            Assert.That(
                new ApplicationUriAttribute().Classification,
                Is.EqualTo(OpcUaDataClasses.ApplicationUri));
            Assert.That(
                new UserIdentityAttribute().Classification,
                Is.EqualTo(OpcUaDataClasses.UserIdentity));
        }

        [Test]
        public void PlainLoggerWithoutPassThroughLosesClassifiedValues()
        {
            // Documents why the pass-through exists: the extended generator
            // only formats classified values the redacting logger filled in.
            using var recorder = new RecordingLoggerProvider();
            using var factory = LoggerFactory.Create(b => b.AddProvider(recorder));

            factory.CreateLogger("Raw").Connecting(kUrl, kPort, kAppUri, kUser, 3);

            RecordedLogRecord record = recorder.Records.Single();
            Assert.That(record.Message, Does.Not.Contain(kUrl));
            Assert.That(record.Message, Does.Contain("(null)"));
            Assert.That(record.Properties.ContainsKey("Url"), Is.False);
        }

        [Test]
        public void TelemetryLoggerKeepsTextAndStateOfStandardGenerator()
        {
            using var recorder = new RecordingLoggerProvider();
            using var factory = LoggerFactory.Create(b => b.AddProvider(recorder));
            ITelemetryContext telemetry = new TestTelemetryContext(factory);

            telemetry.CreateClassifiedLogger<ClassifiedLoggingTests>()
                .Connecting(kUrl, kPort, kAppUri, kUser, 3);
            // LoggerMessage.Define formats like the standard source generator.
            s_reference(factory.CreateLogger("Reference"), kUrl, kPort, kAppUri, kUser, 3, null);

            RecordedLogRecord actual = recorder.Records[0];
            RecordedLogRecord expected = recorder.Records[1];
            Assert.That(actual.Message, Is.EqualTo(expected.Message));
            Assert.That(
                actual.Message,
                Is.EqualTo(
                    "Connecting to opc.tcp://10.1.2.3:4840/plant on port 4840 for " +
                    "urn:plant-host:Line1 as operator7 (3 tries)."));
            Assert.That(actual.CategoryName, Is.EqualTo(typeof(ClassifiedLoggingTests).FullName));
            Assert.That(actual.EventId.Id, Is.EqualTo(expected.EventId.Id));
            AssertSameProperties(actual, expected);
        }

        [Test]
        public void TelemetryLoggerPrintsNullLikeStandardGenerator()
        {
            using var recorder = new RecordingLoggerProvider();
            using var factory = LoggerFactory.Create(b => b.AddProvider(recorder));
            ITelemetryContext telemetry = new TestTelemetryContext(factory);

            telemetry.CreateClassifiedLogger("Category").Connecting(null, kPort, null, null, 0);
            s_reference(factory.CreateLogger("Reference"), null, kPort, null, null, 0, null);

            Assert.That(recorder.Records[0].Message, Is.EqualTo(recorder.Records[1].Message));
            AssertSameProperties(recorder.Records[0], recorder.Records[1]);
        }

        [Test]
        public void PassThroughIsIdempotentAndKeepsTheTypedCategory()
        {
            using var recorder = new RecordingLoggerProvider();
            using var factory = LoggerFactory.Create(b => b.AddProvider(recorder));

            ILogger<ClassifiedLoggingTests> typed =
                factory.CreateClassifiedLogger<ClassifiedLoggingTests>();
            ILogger wrapped = typed.WithClassifiedPassThrough();

            Assert.That(wrapped, Is.SameAs(typed));
            typed.Connecting(kUrl, kPort, kAppUri, kUser, 1);
            Assert.That(
                recorder.Records.Single().CategoryName,
                Is.EqualTo("Opc.Ua.Types.Tests.Diagnostics.ClassifiedLoggingTests"));
        }

        [Test]
        public void DisabledLevelIsNotForwarded()
        {
            using var recorder = new RecordingLoggerProvider(LogLevel.Error);
            using var factory = LoggerFactory.Create(b => b
                .AddProvider(recorder)
                .SetMinimumLevel(LogLevel.Trace));
            ILogger logger = factory.CreateClassifiedLogger("Category");

            logger.Connecting(kUrl, kPort, kAppUri, kUser, 1);

            Assert.That(recorder.Records, Is.Empty);
        }

        [Test]
        public void ErasingRedactorRemovesNetworkAddresses()
        {
            using var recorder = new RecordingLoggerProvider(formatValues: true);
            using ServiceProvider services = CreateRedactingServices(recorder);
            ITelemetryContext telemetry = new TestTelemetryContext(
                services.GetRequiredService<ILoggerFactory>());

            telemetry.CreateClassifiedLogger<ClassifiedLoggingTests>()
                .Connecting(kUrl, kPort, kAppUri, kUser, 3);

            RecordedLogRecord record = recorder.Records.Single();
            Assert.That(
                record.Message,
                Is.EqualTo("Connecting to  on port  for urn:plant-host:Line1 as operator7 (3 tries)."));
            AssertNoValue(record, kUrl, "10.1.2.3", "4840");
            Assert.That(record.Properties["Url"], Is.Empty);
            Assert.That(record.Properties["Port"], Is.Empty);
            Assert.That(record.Properties["AppUri"], Is.EqualTo(kAppUri));
            Assert.That(record.Properties["User"], Is.EqualTo(kUser));
            Assert.That(record.Properties["Count"], Is.EqualTo("3"));
        }

        [Test]
        public void ErasingRedactorAlsoAppliesToTheTypedFactoryLogger()
        {
            using var recorder = new RecordingLoggerProvider(formatValues: true);
            using ServiceProvider services = CreateRedactingServices(recorder);

            // As resolved from dependency injection, then wrapped by a component.
            services.GetRequiredService<ILogger<ClassifiedLoggingTests>>()
                .WithClassifiedPassThrough()
                .Connecting(kUrl, kPort, kAppUri, kUser, 3);

            AssertNoValue(recorder.Records.Single(), kUrl, "10.1.2.3", "4840");
        }

        [Test]
        public void TypedFactoryLoggerWithoutRedactionKeepsTheText()
        {
            using var recorder = new RecordingLoggerProvider(formatValues: true);
            var services = new ServiceCollection();
            services.AddLogging(b => b.AddProvider(recorder));
            using ServiceProvider provider = services.BuildServiceProvider();

            // As a hosted service receives it from dependency injection.
            provider.GetRequiredService<ILogger<ClassifiedLoggingTests>>()
                .WithClassifiedPassThrough()
                .Connecting(kUrl, kPort, kAppUri, kUser, 3);

            RecordedLogRecord record = recorder.Records.Single();
            Assert.That(
                record.Message,
                Is.EqualTo(
                    "Connecting to opc.tcp://10.1.2.3:4840/plant on port 4840 for " +
                    "urn:plant-host:Line1 as operator7 (3 tries)."));
            // Known limitation: Logger<T> may hide a redacting logger, so it
            // gets the original state, which carries the unclassified values only.
            Assert.That(record.Properties.ContainsKey("Url"), Is.False);
            Assert.That(record.Properties["Count"], Is.EqualTo("3"));
        }

        [Test]
        public void RestrictedFactorySplitsGeneralAndRestrictedLog()
        {
            using var general = new RecordingLoggerProvider(formatValues: true);
            using var restricted = new RecordingLoggerProvider(formatValues: true);
            using ServiceProvider services = CreateRedactingServices(general);
            using var restrictedFactory = LoggerFactory.Create(b => b.AddProvider(restricted));
            using var factory = new RestrictedDataLoggerFactory(
                services.GetRequiredService<ILoggerFactory>(),
                restrictedFactory,
                OpcUaDataClasses.NetworkAddress);
            ITelemetryContext telemetry = new TestTelemetryContext(factory);
            ILogger logger = telemetry.CreateClassifiedLogger<ClassifiedLoggingTests>();

            logger.Connecting(kUrl, kPort, kAppUri, kUser, 3);
            logger.Unclassified(5);
            logger.IdentityOnly(kUser);
            logger.Connecting(kUrl + "/second", kPort, kAppUri, kUser, 4);

            Assert.That(general.Records, Has.Count.EqualTo(4));
            foreach (RecordedLogRecord record in general.Records)
            {
                AssertNoValue(record, kUrl, "10.1.2.3", "4840");
            }

            // Only the entries with a network address, with the raw values
            // and without a discriminator suffix.
            Assert.That(restricted.Records, Has.Count.EqualTo(2));
            Assert.That(
                restricted.Records[0].Message,
                Is.EqualTo(
                    "Connecting to opc.tcp://10.1.2.3:4840/plant on port 4840 for " +
                    "urn:plant-host:Line1 as operator7 (3 tries)."));
            Assert.That(restricted.Records[0].Properties["Url"], Is.EqualTo(kUrl));
            Assert.That(restricted.Records[0].Properties["Port"], Is.EqualTo("4840"));
            Assert.That(restricted.Records[1].Properties["Url"], Is.EqualTo(kUrl + "/second"));
            Assert.That(restricted.Records[1].Message, Does.Contain(kUrl + "/second on port 4840"));
        }

        [Test]
        public void RestrictedFactoryRequiresAClassification()
        {
            using var factory = LoggerFactory.Create(_ => { });
            Assert.Throws<ArgumentException>(
                () => _ = new RestrictedDataLoggerFactory(factory, factory));
            Assert.Throws<ArgumentNullException>(
                () => _ = new RestrictedDataLoggerFactory(
                    null!,
                    factory,
                    OpcUaDataClasses.NetworkAddress));
        }

        private static ServiceProvider CreateRedactingServices(RecordingLoggerProvider recorder)
        {
            var services = new ServiceCollection();
            services.AddLogging(b => b
                .AddProvider(recorder)
                .SetMinimumLevel(LogLevel.Trace)
                .EnableRedaction());
            services.AddRedaction(r => r
                .SetRedactor<ErasingRedactor>(
                    new DataClassificationSet(OpcUaDataClasses.NetworkAddress))
                .SetFallbackRedactor<NullRedactor>());
            // Without this the redactor sees "value:TagName", which a
            // pass-through redactor would print verbatim.
            services.Configure<LoggerRedactionOptions>(o => o.ApplyDiscriminator = false);
            return services.BuildServiceProvider();
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
                        Convert.ToString(property.Value, System.Globalization.CultureInfo.InvariantCulture),
                        Does.Not.Contain(value),
                        property.Key);
                }
            }
        }

        private static void AssertSameProperties(RecordedLogRecord actual, RecordedLogRecord expected)
        {
            Assert.That(
                actual.Properties.Keys.OrderBy(k => k, StringComparer.Ordinal),
                Is.EqualTo(expected.Properties.Keys.OrderBy(k => k, StringComparer.Ordinal)));
            foreach (KeyValuePair<string, object?> property in expected.Properties)
            {
                Assert.That(
                    Convert.ToString(actual.Properties[property.Key], System.Globalization.CultureInfo.InvariantCulture),
                    Is.EqualTo(Convert.ToString(property.Value, System.Globalization.CultureInfo.InvariantCulture)),
                    property.Key);
            }
        }

        private static readonly Action<ILogger, string?, int, string?, string?, int, Exception?> s_reference =
            LoggerMessage.Define<string?, int, string?, string?, int>(
                LogLevel.Warning,
                new EventId(1, nameof(ClassifiedLoggingTestLog.Connecting)),
                kTemplate);

        private sealed class TestTelemetryContext : TelemetryContextBase
        {
            public TestTelemetryContext(ILoggerFactory loggerFactory)
                : base(loggerFactory)
            {
            }
        }
    }

    /// <summary>
    /// Messages with classified parameters, generated by the extended
    /// logging source generator.
    /// </summary>
    internal static partial class ClassifiedLoggingTestLog
    {
        [LoggerMessage(EventId = 1, Level = LogLevel.Warning,
            Message = "Connecting to {Url} on port {Port} for {AppUri} as {User} ({Count} tries).")]
        public static partial void Connecting(
            this ILogger logger,
            [NetworkAddress] string? url,
            [NetworkAddress] int port,
            [ApplicationUri] string? appUri,
            [UserIdentity] string? user,
            int count);

        [LoggerMessage(EventId = 2, Level = LogLevel.Information,
            Message = "Nothing classified: {Count}.")]
        public static partial void Unclassified(this ILogger logger, int count);

        [LoggerMessage(EventId = 3, Level = LogLevel.Information,
            Message = "Identity only: {User}.")]
        public static partial void IdentityOnly(this ILogger logger, [UserIdentity] string user);
    }
}
