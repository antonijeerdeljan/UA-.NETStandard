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
using System.Net.Sockets;
using System.Text;

namespace Opc.Ua
{
    /// <summary>
    /// Stands in for an exception in the normal log categories of a
    /// <see cref="SensitiveDataLoggerFactory"/>. Exception messages can
    /// contain network addresses, so the message is replaced by the
    /// placeholder. The type, the status code of a
    /// <see cref="ServiceResultException"/>, the socket error of a
    /// <see cref="SocketException"/>, the HResult, the stack trace and the
    /// inner exceptions (redacted the same way) are kept.
    /// </summary>
    public sealed class SensitiveDataRedactedException : Exception
    {
        /// <summary>
        /// Create an empty redacted exception.
        /// </summary>
        public SensitiveDataRedactedException()
            : this(SensitiveDataLoggerOptions.DefaultPlaceholder)
        {
        }

        /// <summary>
        /// Create a redacted exception with a message.
        /// </summary>
        /// <param name="message">The redacted message.</param>
        public SensitiveDataRedactedException(string message)
            : base(message)
        {
            OriginalTypeName = typeof(Exception).FullName!;
        }

        /// <summary>
        /// Create a redacted exception with a message and an inner exception.
        /// </summary>
        /// <param name="message">The redacted message.</param>
        /// <param name="innerException">The redacted inner exception.</param>
        public SensitiveDataRedactedException(string message, Exception? innerException)
            : base(message, innerException)
        {
            OriginalTypeName = typeof(Exception).FullName!;
        }

        private SensitiveDataRedactedException(
            Exception original,
            string message,
            StatusCode? statusCode,
            Exception? innerException)
            : base(message, innerException)
        {
            OriginalTypeName = original.GetType().FullName ?? original.GetType().Name;
            StatusCode = statusCode;
            HResult = original.HResult;
            m_stackTrace = original.StackTrace;
        }

        /// <summary>
        /// The full name of the type of the original exception.
        /// </summary>
        public string OriginalTypeName { get; }

        /// <summary>
        /// The status code of the original exception, if it was a
        /// <see cref="ServiceResultException"/>.
        /// </summary>
        public StatusCode? StatusCode { get; }

        /// <summary>
        /// The stack trace of the original exception.
        /// </summary>
        public override string? StackTrace => m_stackTrace ?? base.StackTrace;

        /// <summary>
        /// Create the redacted copy of an exception and its inner exceptions.
        /// </summary>
        /// <param name="exception">The exception to redact.</param>
        /// <param name="placeholder">The text that replaces the messages.</param>
        public static SensitiveDataRedactedException Create(Exception exception, string placeholder)
        {
            if (exception == null)
            {
                throw new ArgumentNullException(nameof(exception));
            }
            if (exception is SensitiveDataRedactedException redacted)
            {
                return redacted;
            }

            SensitiveDataRedactedException? inner = exception.InnerException != null
                ? Create(exception.InnerException, placeholder)
                : null;

            StatusCode? statusCode = null;
            string message = placeholder;
            switch (exception)
            {
                case ServiceResultException sre:
                    statusCode = sre.StatusCode;
                    message = string.Format(
                        CultureInfo.InvariantCulture,
                        "{0} ({1})",
                        placeholder,
                        sre.StatusCode.ToString());
                    break;
                case SocketException se:
                    message = string.Format(
                        CultureInfo.InvariantCulture,
                        "{0} ({1})",
                        placeholder,
                        se.SocketErrorCode.ToString());
                    break;
            }
            return new SensitiveDataRedactedException(exception, message, statusCode, inner);
        }

        /// <summary>
        /// Formats like <see cref="Exception.ToString()"/>, but with the
        /// type name of the original exception.
        /// </summary>
        public override string ToString()
        {
            var buffer = new StringBuilder()
                .Append(OriginalTypeName)
                .Append(": ")
                .Append(Message);
            if (InnerException != null)
            {
                buffer
                    .Append(" ---> ")
                    .Append(InnerException.ToString())
                    .AppendLine()
                    .Append("   --- End of inner exception stack trace ---");
            }
            string? stackTrace = StackTrace;
            if (!string.IsNullOrEmpty(stackTrace))
            {
                buffer.AppendLine().Append(stackTrace);
            }
            return buffer.ToString();
        }

        private readonly string? m_stackTrace;
    }
}
