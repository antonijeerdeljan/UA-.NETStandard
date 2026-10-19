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
using System.Globalization;

namespace Opc.Ua
{
    /// <summary>
    /// Marks a log message argument as sensitive, for example an endpoint
    /// URL, an IP address or a port of a plant device.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Formatting a <see cref="SensitiveValue"/> yields the wrapped value, so
    /// log output is unchanged unless the application opts in to splitting.
    /// </para>
    /// <para>
    /// When the logger factory of the telemetry context is a
    /// <see cref="SensitiveDataLoggerFactory"/>, the log entry is written
    /// twice: once to its normal category with the value replaced by
    /// <see cref="RedactedText"/> (or the configured placeholder), and once
    /// with the real value to the sensitive category.
    /// </para>
    /// <para>
    /// <see cref="SensitiveValue"/> is a class and deliberately does not
    /// implement <see cref="IFormattable"/>. The extended logging source
    /// generator of Microsoft.Extensions.Telemetry.Abstractions converts
    /// value type and <see cref="IFormattable"/> arguments to strings while
    /// it creates the log state, before any logger sees the entry, which
    /// would defeat the redaction. Reference type arguments are kept in the
    /// state by both logging source generators.
    /// </para>
    /// </remarks>
    public sealed class SensitiveValue
    {
        /// <summary>
        /// Create a sensitive value.
        /// </summary>
        /// <param name="value">The value to log.</param>
        /// <param name="redactedText">The text to log instead of the value
        /// in redacted output, or <c>null</c> to use the placeholder
        /// configured on the <see cref="SensitiveDataLoggerFactory"/>.</param>
        public SensitiveValue(object? value, string? redactedText = null)
        {
            Value = value;
            RedactedText = redactedText;
        }

        /// <summary>
        /// The wrapped value.
        /// </summary>
        public object? Value { get; }

        /// <summary>
        /// The text that replaces the value in redacted output, or
        /// <c>null</c> to use the configured placeholder.
        /// </summary>
        public string? RedactedText { get; }

        /// <summary>
        /// Wrap a value, or return <c>null</c> for a <c>null</c> value. A
        /// missing value is not sensitive: the logging source generators
        /// format it exactly as before, the entry is not split, and no
        /// wrapper is allocated.
        /// </summary>
        /// <param name="value">The value to log.</param>
        /// <param name="redactedText">The text to log instead of the value
        /// in redacted output, or <c>null</c> to use the placeholder.</param>
        public static SensitiveValue? Create(object? value, string? redactedText = null)
        {
            return value == null ? null : new SensitiveValue(value, redactedText);
        }

        /// <summary>
        /// Wrap a service result. Redacted output keeps the status code and
        /// drops the localized text and additional info, which can contain
        /// exception messages with network addresses.
        /// </summary>
        /// <param name="result">The service result to log.</param>
        public static SensitiveValue? FromServiceResult(ServiceResult? result)
        {
            return result == null ? null : new SensitiveValue(result, result.StatusCode.ToString());
        }

        /// <summary>
        /// The text this value formats to in redacted output.
        /// </summary>
        /// <param name="placeholder">The placeholder used when no
        /// <see cref="RedactedText"/> was provided.</param>
        public string GetRedactedText(string placeholder)
        {
            return RedactedText ?? placeholder;
        }

        /// <summary>
        /// Returns the wrapped value formatted with the invariant culture,
        /// like both logging source generators format arguments, or the
        /// redacted text while a <see cref="SensitiveDataLoggerFactory"/>
        /// formats the redacted copy of a log entry.
        /// </summary>
        /// <remarks>
        /// Format specifiers in the message template are not applied to a
        /// <see cref="SensitiveValue"/>.
        /// </remarks>
        public override string ToString()
        {
            string? placeholder = t_placeholder;
            if (placeholder != null)
            {
                return GetRedactedText(placeholder);
            }
            return Value switch
            {
                // Same text the standard logging formatter emits for null.
                null => kNullValue,
                IFormattable formattable => formattable.ToString(null, CultureInfo.InvariantCulture),
                _ => Value.ToString() ?? string.Empty
            };
        }

        /// <summary>
        /// Makes every <see cref="SensitiveValue"/> formatted on the current
        /// thread return its redacted text until the scope is disposed.
        /// Only the <see cref="SensitiveDataLoggerFactory"/> loggers use it,
        /// around a synchronous call of the log entry's formatter.
        /// </summary>
        internal static RedactionScope BeginRedaction(string placeholder)
        {
            var scope = new RedactionScope(t_placeholder);
            t_placeholder = placeholder;
            return scope;
        }

        /// <summary>
        /// Restores the previous redaction state of the thread.
        /// </summary>
        internal readonly struct RedactionScope : IDisposable
        {
            public RedactionScope(string? previous)
            {
                m_previous = previous;
            }

            public void Dispose()
            {
                t_placeholder = m_previous;
            }

            private readonly string? m_previous;
        }

        private const string kNullValue = "(null)";

        [ThreadStatic]
        private static string? t_placeholder;
    }
}
