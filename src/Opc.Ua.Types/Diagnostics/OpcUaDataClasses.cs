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
using Microsoft.Extensions.Compliance.Classification;

namespace Opc.Ua
{
    /// <summary>
    /// The data classification taxonomy of the OPC UA stack.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Log messages of the stack mark parameters that carry deployment
    /// specific, potentially confidential information with one of these
    /// classes (see <see cref="NetworkAddressAttribute"/>,
    /// <see cref="ApplicationUriAttribute"/> and
    /// <see cref="UserIdentityAttribute"/>). An application can then redact
    /// or route those values using the redaction model of
    /// <c>Microsoft.Extensions.Compliance.Redaction</c>, for example
    /// <c>services.AddRedaction(r => r.SetRedactor&lt;ErasingRedactor&gt;(
    /// new DataClassificationSet(OpcUaDataClasses.NetworkAddress)))</c>
    /// together with <c>ILoggingBuilder.EnableRedaction()</c>.
    /// </para>
    /// <para>
    /// The classification does not change what is logged by default: an
    /// application that does not enable redaction receives the same log
    /// text and structured values as before.
    /// </para>
    /// </remarks>
    public static class OpcUaDataClasses
    {
        /// <summary>
        /// The name of the taxonomy.
        /// </summary>
        public const string TaxonomyName = "OpcUa";

        /// <summary>
        /// Network location of a peer or of the local host: endpoint,
        /// discovery, proxy and reverse connect URLs, IP addresses, host
        /// names, ports and <see cref="System.Net.EndPoint"/> values.
        /// </summary>
        public static DataClassification NetworkAddress { get; } =
            new(TaxonomyName, nameof(NetworkAddress));

        /// <summary>
        /// Identity of an OPC UA application: ApplicationUri, ServerUri,
        /// ProductUri and similar URIs. They usually embed a host name or a
        /// company domain.
        /// </summary>
        public static DataClassification ApplicationUri { get; } =
            new(TaxonomyName, nameof(ApplicationUri));

        /// <summary>
        /// Identity of a user: user names and descriptions of user
        /// identity tokens.
        /// </summary>
        public static DataClassification UserIdentity { get; } =
            new(TaxonomyName, nameof(UserIdentity));
    }

    /// <summary>
    /// Classifies a value as <see cref="OpcUaDataClasses.NetworkAddress"/>.
    /// </summary>
    [AttributeUsage(
        AttributeTargets.Parameter |
        AttributeTargets.Property |
        AttributeTargets.Field |
        AttributeTargets.ReturnValue)]
    public sealed class NetworkAddressAttribute : DataClassificationAttribute
    {
        /// <summary>
        /// Create the attribute.
        /// </summary>
        public NetworkAddressAttribute()
            : base(OpcUaDataClasses.NetworkAddress)
        {
        }
    }

    /// <summary>
    /// Classifies a value as <see cref="OpcUaDataClasses.ApplicationUri"/>.
    /// </summary>
    [AttributeUsage(
        AttributeTargets.Parameter |
        AttributeTargets.Property |
        AttributeTargets.Field |
        AttributeTargets.ReturnValue)]
    public sealed class ApplicationUriAttribute : DataClassificationAttribute
    {
        /// <summary>
        /// Create the attribute.
        /// </summary>
        public ApplicationUriAttribute()
            : base(OpcUaDataClasses.ApplicationUri)
        {
        }
    }

    /// <summary>
    /// Classifies a value as <see cref="OpcUaDataClasses.UserIdentity"/>.
    /// </summary>
    [AttributeUsage(
        AttributeTargets.Parameter |
        AttributeTargets.Property |
        AttributeTargets.Field |
        AttributeTargets.ReturnValue)]
    public sealed class UserIdentityAttribute : DataClassificationAttribute
    {
        /// <summary>
        /// Create the attribute.
        /// </summary>
        public UserIdentityAttribute()
            : base(OpcUaDataClasses.UserIdentity)
        {
        }
    }
}
