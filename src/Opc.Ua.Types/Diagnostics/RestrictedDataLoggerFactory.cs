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
using Microsoft.Extensions.Compliance.Classification;
using Microsoft.Extensions.Logging;

namespace Opc.Ua
{
    /// <summary>
    /// A logger factory that writes every entry to a general logging
    /// pipeline and, in addition, writes the entries that carry a value of
    /// the selected data classes to a restricted logging pipeline.
    /// </summary>
    /// <remarks>
    /// <para>
    /// All providers of one logging pipeline see the same values, because
    /// redaction happens before the providers. To keep classified values in
    /// a restricted log while removing them from the general log, the
    /// application builds two pipelines: the general one with redaction
    /// enabled (<c>ILoggingBuilder.EnableRedaction()</c> and a redactor for
    /// the classes), the restricted one without redaction. This factory
    /// combines them and is passed to the stack as the logger factory of the
    /// <see cref="ITelemetryContext"/>.
    /// </para>
    /// <para>
    /// Entries are forwarded synchronously, first to the general and then
    /// to the restricted pipeline. The factory does not own and does not
    /// dispose the two pipelines.
    /// </para>
    /// </remarks>
    public sealed class RestrictedDataLoggerFactory : ILoggerFactory
    {
        /// <summary>
        /// Create the factory.
        /// </summary>
        /// <param name="general">The general logging pipeline, which
        /// receives every entry. It should redact the selected classes.</param>
        /// <param name="restricted">The restricted logging pipeline, which
        /// receives the entries that carry a value of one of the selected
        /// classes, with the values unredacted. It should not redact.</param>
        /// <param name="classifications">The data classes that select the
        /// entries for the restricted pipeline, for example
        /// <see cref="OpcUaDataClasses.NetworkAddress"/>.</param>
        /// <exception cref="ArgumentNullException">An argument is
        /// <c>null</c>.</exception>
        /// <exception cref="ArgumentException">No data class is
        /// given.</exception>
        public RestrictedDataLoggerFactory(
            ILoggerFactory general,
            ILoggerFactory restricted,
            params DataClassification[] classifications)
        {
            m_general = general ?? throw new ArgumentNullException(nameof(general));
            m_restricted = restricted ?? throw new ArgumentNullException(nameof(restricted));
            if (classifications == null)
            {
                throw new ArgumentNullException(nameof(classifications));
            }
            if (classifications.Length == 0)
            {
                throw new ArgumentException(
                    "At least one data classification is required.",
                    nameof(classifications));
            }
            m_classifications = new DataClassificationSet[classifications.Length];
            for (int ii = 0; ii < classifications.Length; ii++)
            {
                m_classifications[ii] = new DataClassificationSet(classifications[ii]);
            }
        }

        /// <inheritdoc/>
        /// <remarks>
        /// The provider is added to the general pipeline.
        /// </remarks>
        public void AddProvider(ILoggerProvider provider)
        {
            m_general.AddProvider(provider);
        }

        /// <inheritdoc/>
        public ILogger CreateLogger(string categoryName)
        {
            return new RoutingLogger(
                m_general.CreateLogger(categoryName).WithClassifiedPassThrough(),
                m_restricted.CreateLogger(categoryName).WithClassifiedPassThrough(),
                m_classifications);
        }

        /// <inheritdoc/>
        /// <remarks>
        /// The pipelines are owned by the caller and are not disposed.
        /// </remarks>
        public void Dispose()
        {
        }

        /// <summary>
        /// Logger that routes entries to the two pipelines.
        /// </summary>
        private sealed class RoutingLogger : ILogger, ClassifiedLogging.IClassifiedDataAwareLogger
        {
            public RoutingLogger(
                ILogger general,
                ILogger restricted,
                DataClassificationSet[] classifications)
            {
                m_general = general;
                m_restricted = restricted;
                m_classifications = classifications;
            }

            /// <inheritdoc/>
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull
            {
                IDisposable? general = m_general.BeginScope(state);
                IDisposable? restricted = m_restricted.BeginScope(state);
                if (general == null)
                {
                    return restricted;
                }
                if (restricted == null)
                {
                    return general;
                }
                return new Scopes(general, restricted);
            }

            /// <inheritdoc/>
            public bool IsEnabled(LogLevel logLevel)
            {
                return m_general.IsEnabled(logLevel) || m_restricted.IsEnabled(logLevel);
            }

            /// <inheritdoc/>
            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                m_general.Log(logLevel, eventId, state, exception, formatter);
                if (typeof(TState) == typeof(LoggerMessageState) &&
                    state is LoggerMessageState messageState &&
                    IsRestricted(messageState))
                {
                    // The general pipeline may have left redacted values in
                    // the state. The pass-through logger of the restricted
                    // pipeline replaces them with the raw values.
                    m_restricted.Log(logLevel, eventId, state, exception, formatter);
                }
            }

            private bool IsRestricted(LoggerMessageState state)
            {
                LoggerMessageState.ClassifiedTag[] tags = state.ClassifiedTagArray;
                for (int ii = 0; ii < state.ClassifiedTagsCount; ii++)
                {
                    foreach (DataClassificationSet classification in m_classifications)
                    {
                        if (tags[ii].Classifications.Equals(classification))
                        {
                            return true;
                        }
                    }
                }
                return false;
            }

            private sealed class Scopes : IDisposable
            {
                public Scopes(IDisposable first, IDisposable second)
                {
                    m_first = first;
                    m_second = second;
                }

                public void Dispose()
                {
                    m_second.Dispose();
                    m_first.Dispose();
                }

                private readonly IDisposable m_first;
                private readonly IDisposable m_second;
            }

            private readonly ILogger m_general;
            private readonly ILogger m_restricted;
            private readonly DataClassificationSet[] m_classifications;
        }

        private readonly ILoggerFactory m_general;
        private readonly ILoggerFactory m_restricted;
        private readonly DataClassificationSet[] m_classifications;
    }
}
