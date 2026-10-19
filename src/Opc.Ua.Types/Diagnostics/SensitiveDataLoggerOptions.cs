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

namespace Opc.Ua
{
    /// <summary>
    /// Options of the <see cref="SensitiveDataLoggerFactory"/>.
    /// </summary>
    public sealed class SensitiveDataLoggerOptions
    {
        /// <summary>
        /// The default prefix of the sensitive categories.
        /// </summary>
        public const string DefaultSensitiveCategoryPrefix = "Sensitive.";

        /// <summary>
        /// The default text that replaces a sensitive value.
        /// </summary>
        public const string DefaultPlaceholder = "[redacted]";

        /// <summary>
        /// The prefix prepended to the category of a logger to form the
        /// category that receives the unredacted entries. With the default
        /// prefix, the full entries of <c>Opc.Ua.Client.Session</c> are
        /// written to <c>Sensitive.Opc.Ua.Client.Session</c>.
        /// </summary>
        public string SensitiveCategoryPrefix { get; set; } = DefaultSensitiveCategoryPrefix;

        /// <summary>
        /// The text that replaces a <see cref="SensitiveValue"/> without
        /// its own <see cref="SensitiveValue.RedactedText"/>.
        /// </summary>
        public string Placeholder { get; set; } = DefaultPlaceholder;

        /// <summary>
        /// Whether exceptions are replaced by a
        /// <see cref="SensitiveDataRedactedException"/> in the normal
        /// categories. The redacted exception keeps the exception type, the
        /// status code of a <see cref="ServiceResultException"/> and the
        /// stack trace, but no message, because exception messages can
        /// contain network addresses. The default is <c>true</c>.
        /// </summary>
        public bool RedactExceptions { get; set; } = true;
    }
}
