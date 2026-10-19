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
using System.Collections;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;

namespace Opc.Ua
{
    /// <summary>
    /// A logger factory that splits log entries carrying sensitive data
    /// into a redacted entry in the normal category and a complete entry
    /// in a separate sensitive category.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Pass an instance as the <see cref="ITelemetryContext.LoggerFactory"/>
    /// of the telemetry context to opt in. The loggers it creates:
    /// </para>
    /// <list type="bullet">
    /// <item>pass entries without a <see cref="SensitiveValue"/> argument
    /// and without an exception through unchanged;</item>
    /// <item>otherwise write the entry to its normal category with the
    /// same level and event id, but with every <see cref="SensitiveValue"/>
    /// replaced by its redacted text, both in the message and in the
    /// structured state, and with the exception redacted;</item>
    /// <item>and write the original entry to the category named
    /// <see cref="SensitiveDataLoggerOptions.SensitiveCategoryPrefix"/>
    /// followed by the normal category.</item>
    /// </list>
    /// <para>
    /// Route the categories with the standard filters and providers of the
    /// wrapped factory. A rule for the category <c>Sensitive</c> matches all
    /// sensitive categories when the default prefix is used.
    /// </para>
    /// <para>
    /// Disposing this factory disposes the wrapped factory.
    /// </para>
    /// </remarks>
    public sealed class SensitiveDataLoggerFactory : ILoggerFactory
    {
        /// <summary>
        /// Wrap a logger factory.
        /// </summary>
        /// <param name="loggerFactory">The factory that creates the loggers
        /// of the normal and the sensitive categories.</param>
        /// <param name="options">The options, or <c>null</c> for the
        /// defaults.</param>
        /// <exception cref="ArgumentNullException"><paramref name="loggerFactory"/>
        /// is <c>null</c>.</exception>
        /// <exception cref="ArgumentException">The prefix or placeholder of
        /// <paramref name="options"/> is <c>null</c> or empty.</exception>
        public SensitiveDataLoggerFactory(
            ILoggerFactory loggerFactory,
            SensitiveDataLoggerOptions? options = null)
        {
            m_loggerFactory = loggerFactory ??
                throw new ArgumentNullException(nameof(loggerFactory));
            options ??= new SensitiveDataLoggerOptions();
            if (string.IsNullOrEmpty(options.SensitiveCategoryPrefix))
            {
                throw new ArgumentException(
                    "The sensitive category prefix must not be empty.",
                    nameof(options));
            }
            if (string.IsNullOrEmpty(options.Placeholder))
            {
                throw new ArgumentException(
                    "The placeholder must not be empty.",
                    nameof(options));
            }

            // Copy so later changes to the options cannot affect the loggers.
            m_prefix = options.SensitiveCategoryPrefix;
            m_placeholder = options.Placeholder;
            m_redactExceptions = options.RedactExceptions;
        }

        /// <inheritdoc/>
        public ILogger CreateLogger(string categoryName)
        {
            if (categoryName.StartsWith(m_prefix, StringComparison.Ordinal))
            {
                // Already a sensitive category, do not split it again.
                return m_loggerFactory.CreateLogger(categoryName);
            }
            return new SensitiveDataLogger(
                m_loggerFactory.CreateLogger(categoryName),
                m_loggerFactory.CreateLogger(m_prefix + categoryName),
                m_placeholder,
                m_redactExceptions);
        }

        /// <inheritdoc/>
        public void AddProvider(ILoggerProvider provider)
        {
            m_loggerFactory.AddProvider(provider);
        }

        /// <inheritdoc/>
        public void Dispose()
        {
            m_loggerFactory.Dispose();
        }

        /// <summary>
        /// Splits the entries of one category.
        /// </summary>
        private sealed class SensitiveDataLogger : ILogger
        {
            public SensitiveDataLogger(
                ILogger normal,
                ILogger sensitive,
                string placeholder,
                bool redactExceptions)
            {
                m_normal = normal;
                m_sensitive = sensitive;
                m_placeholder = placeholder;
                m_redactExceptions = redactExceptions;
            }

            /// <inheritdoc/>
            public IDisposable? BeginScope<TState>(TState state)
                where TState : notnull
            {
                // Scopes are kept by the scope provider of the wrapped
                // factory, which both categories share. Pushing the scope
                // through both loggers would duplicate it.
                return m_normal.BeginScope(state);
            }

            /// <inheritdoc/>
            public bool IsEnabled(LogLevel logLevel)
            {
                return m_normal.IsEnabled(logLevel) || m_sensitive.IsEnabled(logLevel);
            }

            /// <inheritdoc/>
            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                bool hasSensitiveValue = ContainsSensitiveValue(state);
                bool redactException = exception != null && m_redactExceptions;
                if (!hasSensitiveValue && !redactException)
                {
                    m_normal.Log(logLevel, eventId, state, exception, formatter);
                    return;
                }

                if (m_normal.IsEnabled(logLevel))
                {
                    Exception? redactedException = redactException
                        ? SensitiveDataRedactedException.Create(exception!, m_placeholder)
                        : exception;
                    if (hasSensitiveValue)
                    {
                        string message;
                        using (SensitiveValue.BeginRedaction(m_placeholder))
                        {
                            message = formatter(state, redactedException);
                        }
                        m_normal.Log(
                            logLevel,
                            eventId,
                            new RedactedLogState(state, message, m_placeholder),
                            redactedException,
                            static (s, _) => s.ToString());
                    }
                    else
                    {
                        m_normal.Log(logLevel, eventId, state, redactedException, formatter);
                    }
                }

                if (m_sensitive.IsEnabled(logLevel))
                {
                    m_sensitive.Log(logLevel, eventId, state, exception, formatter);
                }
            }

            private static bool ContainsSensitiveValue<TState>(TState state)
            {
                if (state is IReadOnlyList<KeyValuePair<string, object?>> list)
                {
                    for (int ii = 0; ii < list.Count; ii++)
                    {
                        if (list[ii].Value is SensitiveValue)
                        {
                            return true;
                        }
                    }
                }
                else if (state is IEnumerable<KeyValuePair<string, object?>> values)
                {
                    foreach (KeyValuePair<string, object?> value in values)
                    {
                        if (value.Value is SensitiveValue)
                        {
                            return true;
                        }
                    }
                }
                return false;
            }

            private readonly ILogger m_normal;
            private readonly ILogger m_sensitive;
            private readonly string m_placeholder;
            private readonly bool m_redactExceptions;
        }

        /// <summary>
        /// The state of a redacted entry: the structured values of the
        /// original state with every <see cref="SensitiveValue"/> replaced
        /// by its redacted text, and the precomputed redacted message.
        /// The <c>{OriginalFormat}</c> value is kept.
        /// </summary>
        private sealed class RedactedLogState : IReadOnlyList<KeyValuePair<string, object?>>
        {
            public RedactedLogState(object? state, string message, string placeholder)
            {
                m_message = message;
                var values = new List<KeyValuePair<string, object?>>();
                if (state is IEnumerable<KeyValuePair<string, object?>> original)
                {
                    foreach (KeyValuePair<string, object?> value in original)
                    {
                        values.Add(value.Value is SensitiveValue sensitive
                            ? new KeyValuePair<string, object?>(
                                value.Key,
                                sensitive.GetRedactedText(placeholder))
                            : value);
                    }
                }
                m_values = values;
            }

            public KeyValuePair<string, object?> this[int index] => m_values[index];

            public int Count => m_values.Count;

            public IEnumerator<KeyValuePair<string, object?>> GetEnumerator()
            {
                return m_values.GetEnumerator();
            }

            IEnumerator IEnumerable.GetEnumerator()
            {
                return GetEnumerator();
            }

            public override string ToString()
            {
                return m_message;
            }

            private readonly List<KeyValuePair<string, object?>> m_values;
            private readonly string m_message;
        }

        private readonly ILoggerFactory m_loggerFactory;
        private readonly string m_prefix;
        private readonly string m_placeholder;
        private readonly bool m_redactExceptions;
    }
}
