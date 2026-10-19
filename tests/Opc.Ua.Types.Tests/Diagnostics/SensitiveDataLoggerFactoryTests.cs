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
using System.IO;
using System.Linq;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using Opc.Ua.Tests;

// The tests log unconditionally to assert on the recorded entries.
#pragma warning disable CA1873

namespace Opc.Ua.Types.Tests.Diagnostics
{
    /// <summary>
    /// Tests for <see cref="SensitiveValue"/> and <see cref="SensitiveDataLoggerFactory"/>.
    /// </summary>
    [TestFixture]
    [SetCulture("en-us")]
    [Parallelizable]
    public class SensitiveDataLoggerFactoryTests
    {
        private const string kCategory = "Opc.Ua.Test.Channel";
        private const string kSensitiveCategory = "Sensitive." + kCategory;
        private const string kEndpointUrl = "opc.tcp://10.1.2.3:4840/plant";
        private const string kAddress = "10.1.2.3";
        private const string kPort = "4840";

        private static readonly StatusCode s_badNotConnected = new(0x808A0000, "BadNotConnected");

        [Test]
        public void WithoutWrapperOutputIsUnchanged()
        {
            var provider = new RecordingLoggerProvider();
            using ILoggerFactory factory = CreateFactory(provider);
            ILogger logger = factory.CreateLogger(kCategory);
            ServiceResult result = CreateServiceResultWithAddress();

            LegacyTestLog.LegacyConnectFailed(logger, null, kEndpointUrl, result, 3);
            logger.ConnectFailed(null, new SensitiveValue(kEndpointUrl),
                SensitiveValue.FromServiceResult(result), 3);

            IReadOnlyList<RecordedLogRecord> records = provider.Records;
            Assert.That(records, Has.Count.EqualTo(2));
            RecordedLogRecord legacy = records[0];
            RecordedLogRecord converted = records[1];
            Assert.That(converted.CategoryName, Is.EqualTo(kCategory));
            Assert.That(converted.Message, Is.EqualTo(legacy.Message));
            Assert.That(converted.Message, Does.Contain(kEndpointUrl));
            Assert.That(converted.Message, Does.Contain(kAddress + ":" + kPort));
            Assert.That(converted.LogLevel, Is.EqualTo(legacy.LogLevel));
            Assert.That(converted.EventId.Id, Is.EqualTo(legacy.EventId.Id));
            Assert.That(
                converted.Properties.Keys,
                Is.EquivalentTo(legacy.Properties.Keys));
            foreach (KeyValuePair<string, object?> value in legacy.Properties)
            {
                Assert.That(
                    Convert.ToString(converted.Properties[value.Key], System.Globalization.CultureInfo.InvariantCulture),
                    Is.EqualTo(Convert.ToString(value.Value, System.Globalization.CultureInfo.InvariantCulture)),
                    value.Key);
            }
        }

        [Test]
        public void NullSensitiveValueFormatsLikeNullArgument()
        {
            var provider = new RecordingLoggerProvider();
            using ILoggerFactory factory = CreateFactory(provider);
            ILogger logger = factory.CreateLogger(kCategory);

            LegacyTestLog.LegacyEndpointSelected(logger, null);
            logger.EndpointSelected(SensitiveValue.Create(null));

            IReadOnlyList<RecordedLogRecord> records = provider.Records;
            Assert.That(records[1].Message, Is.EqualTo(records[0].Message));
        }

        [Test]
        public void WithWrapperNormalCategoryIsRedactedAndSensitiveCategoryIsComplete()
        {
            var provider = new RecordingLoggerProvider();
            using var factory = new SensitiveDataLoggerFactory(CreateFactory(provider));
            ILogger logger = factory.CreateLogger(kCategory);
            ServiceResult result = CreateServiceResultWithAddress();

            logger.ConnectFailed(null, new SensitiveValue(kEndpointUrl),
                SensitiveValue.FromServiceResult(result), 3);

            RecordedLogRecord normal = Single(provider, kCategory);
            RecordedLogRecord sensitive = Single(provider, kSensitiveCategory);

            AssertNoAddress(normal);
            Assert.That(normal.Message, Is.EqualTo(
                "Connect to [redacted] failed: BadNotConnected, Count=3"));
            Assert.That(normal.Properties["EndpointUrl"], Is.EqualTo("[redacted]"));
            Assert.That(normal.Properties["ServiceResult"], Is.EqualTo("BadNotConnected"));
            Assert.That(normal.Properties["Count"], Is.EqualTo(3));
            Assert.That(
                normal.Properties["{OriginalFormat}"],
                Is.EqualTo("Connect to {EndpointUrl} failed: {ServiceResult}, Count={Count}"));

            Assert.That(sensitive.Message, Is.EqualTo(
                $"Connect to {kEndpointUrl} failed: {result}, Count=3"));
            Assert.That(sensitive.Message, Does.Contain(kAddress + ":" + kPort));
            Assert.That(
                sensitive.Properties["EndpointUrl"]?.ToString(),
                Is.EqualTo(kEndpointUrl));
        }

        [Test]
        public void LevelAndEventIdArePreservedOnBothStreams()
        {
            var provider = new RecordingLoggerProvider();
            using var factory = new SensitiveDataLoggerFactory(CreateFactory(provider));
            ILogger logger = factory.CreateLogger(kCategory);

            logger.ConnectFailed(null, new SensitiveValue(kEndpointUrl),
                SensitiveValue.FromServiceResult(ServiceResult.Good), 1);
            logger.EndpointSelected(new SensitiveValue(kEndpointUrl));

            RecordedLogRecord[] normal = [.. provider.Records.Where(r => r.CategoryName == kCategory)];
            RecordedLogRecord[] sensitive = [.. provider.Records.Where(r => r.CategoryName == kSensitiveCategory)];
            Assert.That(normal, Has.Length.EqualTo(2));
            Assert.That(sensitive, Has.Length.EqualTo(2));
            for (int ii = 0; ii < 2; ii++)
            {
                Assert.That(sensitive[ii].LogLevel, Is.EqualTo(normal[ii].LogLevel));
                Assert.That(sensitive[ii].EventId, Is.EqualTo(normal[ii].EventId));
            }
            Assert.That(normal[0].LogLevel, Is.EqualTo(LogLevel.Error));
            Assert.That(normal[0].EventId.Id, Is.EqualTo(TestLog.ConnectFailedId));
            Assert.That(normal[0].EventId.Name, Is.EqualTo(nameof(TestLog.ConnectFailed)));
            Assert.That(normal[1].LogLevel, Is.EqualTo(LogLevel.Debug));
            Assert.That(normal[1].EventId.Id, Is.EqualTo(TestLog.EndpointSelectedId));
        }

        [Test]
        public void EntriesWithoutSensitiveDataArePassedThroughOnce()
        {
            var provider = new RecordingLoggerProvider();
            using var factory = new SensitiveDataLoggerFactory(CreateFactory(provider));
            ILogger logger = factory.CreateLogger(kCategory);

            logger.Plain(42);
            if (logger.IsEnabled(LogLevel.Information))
            {
                logger.LogInformation("Free form {Value}", 7);
            }

            IReadOnlyList<RecordedLogRecord> records = provider.Records;
            Assert.That(records, Has.Count.EqualTo(2));
            Assert.That(records.Select(r => r.CategoryName), Is.All.EqualTo(kCategory));
            Assert.That(records[0].Message, Is.EqualTo("Plain message 42"));
            Assert.That(records[0].Properties["Count"], Is.EqualTo(42));
            Assert.That(records[0].EventId.Id, Is.EqualTo(TestLog.PlainId));
            Assert.That(records[1].Message, Is.EqualTo("Free form 7"));
        }

        [Test]
        public void ExceptionsAreRedactedOnNormalStreamAndCompleteOnSensitiveStream()
        {
            var provider = new RecordingLoggerProvider();
            using var factory = new SensitiveDataLoggerFactory(CreateFactory(provider));
            ILogger logger = factory.CreateLogger(kCategory);
            ServiceResultException exception = ThrowWrappedSocketError();

            logger.ConnectFailed(exception, new SensitiveValue(kEndpointUrl),
                SensitiveValue.FromServiceResult(exception.Result), 1);

            RecordedLogRecord normal = Single(provider, kCategory);
            RecordedLogRecord sensitive = Single(provider, kSensitiveCategory);

            AssertNoAddress(normal);
            SensitiveDataRedactedException redacted =
                (SensitiveDataRedactedException)normal.Exception!;
            Assert.That(redacted.OriginalTypeName, Is.EqualTo(typeof(ServiceResultException).FullName));
            Assert.That(redacted.StatusCode, Is.EqualTo(s_badNotConnected));
            Assert.That(redacted.HResult, Is.EqualTo(exception.HResult));
            Assert.That(redacted.StackTrace, Is.Not.Empty);
            Assert.That(redacted.StackTrace, Is.EqualTo(exception.StackTrace));
            Assert.That(redacted.Message, Is.EqualTo("[redacted] (BadNotConnected)"));

            var inner = (SensitiveDataRedactedException)redacted.InnerException!;
            Assert.That(inner.OriginalTypeName, Is.EqualTo(typeof(IOException).FullName));
            Assert.That(inner.StackTrace, Is.EqualTo(exception.InnerException!.StackTrace));

            string text = redacted.ToString();
            Assert.That(text, Does.StartWith(
                typeof(ServiceResultException).FullName + ": [redacted] (BadNotConnected) ---> " +
                typeof(IOException).FullName + ": [redacted]"));
            Assert.That(text, Does.Contain(nameof(ThrowWrappedSocketError)));
            Assert.That(text, Does.Not.Contain(kAddress));

            Assert.That(sensitive.Exception, Is.SameAs(exception));
            Assert.That(
                sensitive.Exception!.InnerException!.Message,
                Does.Contain(kAddress + ":" + kPort));
        }

        [Test]
        public void ExceptionOnlyEntriesAreSplit()
        {
            var provider = new RecordingLoggerProvider();
            using var factory = new SensitiveDataLoggerFactory(CreateFactory(provider));
            ILogger logger = factory.CreateLogger(kCategory);
            ServiceResultException exception = ThrowWrappedSocketError();

            logger.PlainError(exception, 5);

            RecordedLogRecord normal = Single(provider, kCategory);
            RecordedLogRecord sensitive = Single(provider, kSensitiveCategory);
            Assert.That(normal.Message, Is.EqualTo("Plain error 5"));
            Assert.That(normal.Exception, Is.TypeOf<SensitiveDataRedactedException>());
            Assert.That(normal.Exception!.ToString(), Does.Not.Contain(kAddress));
            Assert.That(normal.LogLevel, Is.EqualTo(LogLevel.Error));
            Assert.That(sensitive.Exception, Is.SameAs(exception));
            Assert.That(sensitive.EventId, Is.EqualTo(normal.EventId));
        }

        [Test]
        public void ExceptionsPassThroughWhenRedactionIsDisabled()
        {
            var provider = new RecordingLoggerProvider();
            using var factory = new SensitiveDataLoggerFactory(
                CreateFactory(provider),
                new SensitiveDataLoggerOptions { RedactExceptions = false });
            ILogger logger = factory.CreateLogger(kCategory);
            ServiceResultException exception = ThrowWrappedSocketError();

            logger.PlainError(exception, 5);

            RecordedLogRecord normal = Single(provider, kCategory);
            Assert.That(normal.Exception, Is.SameAs(exception));
            Assert.That(provider.Records, Has.Count.EqualTo(1));
        }

        [Test]
        public void OptionsSetPrefixAndPlaceholder()
        {
            var provider = new RecordingLoggerProvider();
            using var factory = new SensitiveDataLoggerFactory(
                CreateFactory(provider),
                new SensitiveDataLoggerOptions
                {
                    SensitiveCategoryPrefix = "Restricted/",
                    Placeholder = "***"
                });
            ILogger logger = factory.CreateLogger(kCategory);

            logger.EndpointSelected(new SensitiveValue(kEndpointUrl));

            Assert.That(Single(provider, kCategory).Message, Is.EqualTo("Selected endpoint ***"));
            Assert.That(
                Single(provider, "Restricted/" + kCategory).Message,
                Is.EqualTo("Selected endpoint " + kEndpointUrl));
        }

        [Test]
        public void FiltersRouteTheStreams()
        {
            var provider = new RecordingLoggerProvider();
            using var factory = new SensitiveDataLoggerFactory(
                LoggerFactory.Create(builder => builder
                    .SetMinimumLevel(LogLevel.Trace)
                    .AddFilter("Sensitive", LogLevel.Error)
                    .AddProvider(provider)));
            ILogger logger = factory.CreateLogger(kCategory);

            logger.EndpointSelected(new SensitiveValue(kEndpointUrl));
            logger.ConnectFailed(null, new SensitiveValue(kEndpointUrl),
                SensitiveValue.FromServiceResult(ServiceResult.Good), 1);

            Assert.That(provider.Records.Count(r => r.CategoryName == kCategory), Is.EqualTo(2));
            RecordedLogRecord sensitive = Single(provider, kSensitiveCategory);
            Assert.That(sensitive.LogLevel, Is.EqualTo(LogLevel.Error));
        }

        [Test]
        public void SensitiveOnlyLevelIsEnabledAndNormalStreamStaysFiltered()
        {
            var provider = new RecordingLoggerProvider();
            using var factory = new SensitiveDataLoggerFactory(
                LoggerFactory.Create(builder => builder
                    .SetMinimumLevel(LogLevel.Information)
                    .AddFilter("Sensitive", LogLevel.Trace)
                    .AddProvider(provider)));
            ILogger logger = factory.CreateLogger(kCategory);

            Assert.That(logger.IsEnabled(LogLevel.Debug), Is.True);
            logger.EndpointSelected(new SensitiveValue(kEndpointUrl));

            RecordedLogRecord sensitive = Single(provider, kSensitiveCategory);
            Assert.That(sensitive.LogLevel, Is.EqualTo(LogLevel.Debug));
            Assert.That(provider.Records, Has.Count.EqualTo(1));
        }

        [Test]
        public void SensitiveCategoriesAreNotSplitAgain()
        {
            var provider = new RecordingLoggerProvider();
            using var factory = new SensitiveDataLoggerFactory(CreateFactory(provider));
            ILogger logger = factory.CreateLogger(kSensitiveCategory);

            logger.EndpointSelected(new SensitiveValue(kEndpointUrl));

            RecordedLogRecord record = Single(provider, kSensitiveCategory);
            Assert.That(record.Message, Does.Contain(kEndpointUrl));
            Assert.That(provider.Records, Has.Count.EqualTo(1));
        }

        [Test]
        public void RedactionIsScopedToTheFormatterCall()
        {
            var provider = new RecordingLoggerProvider();
            using var factory = new SensitiveDataLoggerFactory(CreateFactory(provider));
            ILogger logger = factory.CreateLogger(kCategory);
            var value = new SensitiveValue(kEndpointUrl);

            logger.EndpointSelected(value);

            Assert.That(value.ToString(), Is.EqualTo(kEndpointUrl));
            Assert.That(new SensitiveValue(null).ToString(), Is.EqualTo("(null)"));
            Assert.That(SensitiveValue.Create(null), Is.Null);
            Assert.That(SensitiveValue.FromServiceResult(null), Is.Null);
        }

        [Test]
        public void ConstructorValidatesArguments()
        {
            using ILoggerFactory inner = CreateFactory(new RecordingLoggerProvider());
            Assert.That(
                () => new SensitiveDataLoggerFactory(null!),
                Throws.ArgumentNullException);
            Assert.That(
                () => new SensitiveDataLoggerFactory(
                    inner,
                    new SensitiveDataLoggerOptions { SensitiveCategoryPrefix = string.Empty }),
                Throws.ArgumentException);
            Assert.That(
                () => new SensitiveDataLoggerFactory(
                    inner,
                    new SensitiveDataLoggerOptions { Placeholder = string.Empty }),
                Throws.ArgumentException);
        }

        private static ILoggerFactory CreateFactory(RecordingLoggerProvider provider)
        {
            return LoggerFactory.Create(builder => builder
                .SetMinimumLevel(LogLevel.Trace)
                .AddProvider(provider));
        }

        private static RecordedLogRecord Single(RecordingLoggerProvider provider, string category)
        {
            RecordedLogRecord[] records = [.. provider.Records.Where(r => r.CategoryName == category)];
            Assert.That(records, Has.Length.EqualTo(1), category);
            return records[0];
        }

        private static void AssertNoAddress(RecordedLogRecord record)
        {
            Assert.That(record.Message, Does.Not.Contain(kAddress));
            Assert.That(record.Message, Does.Not.Contain(kPort));
            foreach (KeyValuePair<string, object?> value in record.Properties)
            {
                Assert.That(value.Value, Is.Not.TypeOf<SensitiveValue>(), value.Key);
                string? text = Convert.ToString(value.Value, System.Globalization.CultureInfo.InvariantCulture);
                Assert.That(text, Does.Not.Contain(kAddress), value.Key);
                Assert.That(text, Does.Not.Contain(kPort), value.Key);
            }
            if (record.Exception != null)
            {
                Assert.That(record.Exception.ToString(), Does.Not.Contain(kAddress));
                Assert.That(record.Exception.Message, Does.Not.Contain(kAddress));
            }
        }

        private static ServiceResult CreateServiceResultWithAddress()
        {
            var result = new ServiceResult(
                s_badNotConnected,
                new LocalizedText("Could not connect to " + kAddress + ":" + kPort));
            Assert.That(result.ToString(), Does.Contain(kAddress + ":" + kPort));
            return result;
        }

        /// <summary>
        /// Mirrors how the TCP channel wraps a socket error: the address is
        /// only in the message of the inner exception.
        /// </summary>
        private static ServiceResultException ThrowWrappedSocketError()
        {
            try
            {
                try
                {
                    throw new IOException("Connection refused " + kAddress + ":" + kPort);
                }
                catch (IOException e)
                {
                    throw new ServiceResultException(
                        s_badNotConnected,
                        "Could not connect to the remote endpoint.",
                        e);
                }
            }
            catch (ServiceResultException e)
            {
                return e;
            }
        }
    }

    /// <summary>
    /// Source-generated messages in the same shape as the stack messages.
    /// </summary>
    internal static partial class TestLog
    {
        public const int ConnectFailedId = 4711;
        public const int EndpointSelectedId = 4712;
        public const int PlainId = 4713;
        public const int PlainErrorId = 4714;

        [LoggerMessage(EventId = ConnectFailedId, Level = LogLevel.Error,
            Message = "Connect to {EndpointUrl} failed: {ServiceResult}, Count={Count}")]
        public static partial void ConnectFailed(
            this ILogger logger,
            Exception? exception,
            SensitiveValue? endpointUrl,
            SensitiveValue? serviceResult,
            int count);

        [LoggerMessage(EventId = EndpointSelectedId, Level = LogLevel.Debug,
            Message = "Selected endpoint {EndpointUrl}")]
        public static partial void EndpointSelected(this ILogger logger, SensitiveValue? endpointUrl);

        [LoggerMessage(EventId = PlainId, Level = LogLevel.Information,
            Message = "Plain message {Count}")]
        public static partial void Plain(this ILogger logger, int count);

        [LoggerMessage(EventId = PlainErrorId, Level = LogLevel.Error,
            Message = "Plain error {Count}")]
        public static partial void PlainError(this ILogger logger, Exception? exception, int count);
    }

    /// <summary>
    /// The messages of <see cref="TestLog"/> with the parameter types used
    /// before the conversion to <see cref="SensitiveValue"/>.
    /// </summary>
    internal static partial class LegacyTestLog
    {
        [LoggerMessage(EventId = TestLog.ConnectFailedId, Level = LogLevel.Error,
            Message = "Connect to {EndpointUrl} failed: {ServiceResult}, Count={Count}")]
        public static partial void LegacyConnectFailed(
            this ILogger logger,
            Exception? exception,
            string? endpointUrl,
            ServiceResult serviceResult,
            int count);

        [LoggerMessage(EventId = TestLog.EndpointSelectedId, Level = LogLevel.Debug,
            Message = "Selected endpoint {EndpointUrl}")]
        public static partial void LegacyEndpointSelected(this ILogger logger, Uri? endpointUrl);
    }
}
