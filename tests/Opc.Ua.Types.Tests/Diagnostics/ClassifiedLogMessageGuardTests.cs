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

// A source scan; running it on one target framework is enough.
#if NET8_0_OR_GREATER
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using NUnit.Framework;

namespace Opc.Ua.Types.Tests.Diagnostics
{
    /// <summary>
    /// Regression guard for the data classification of log messages: every
    /// <c>[LoggerMessage]</c> in <c>src/</c> whose template names a network
    /// address, an application URI or a user identity must classify the
    /// parameter, and the project must use the extended logging source
    /// generator that honors the classification.
    /// </summary>
    [TestFixture]
    [Category("Diagnostics")]
    [Parallelizable]
    public class ClassifiedLogMessageGuardTests
    {
        /// <summary>
        /// Placeholder names (case insensitive, as the generator binds them)
        /// and the attribute their parameter must carry.
        /// </summary>
        private static readonly Dictionary<string, string> s_sensitivePlaceholders =
            new(StringComparer.OrdinalIgnoreCase)
            {
                ["EndpointUrl"] = "NetworkAddress",
                ["Endpoint"] = "NetworkAddress",
                ["Url"] = "NetworkAddress",
                ["RemoteEndpoint"] = "NetworkAddress",
                ["Uri"] = "NetworkAddress",
                ["Port"] = "NetworkAddress",
                ["IpAddress"] = "NetworkAddress",
                ["DiscoveryUrl"] = "NetworkAddress",
                ["ClientUrl"] = "NetworkAddress",
                ["Proxy"] = "NetworkAddress",
                ["ListenUri"] = "NetworkAddress",
                ["IdnHost"] = "NetworkAddress",
                ["Host"] = "NetworkAddress",
                ["BootstrapServers"] = "NetworkAddress",
                ["ServerDomainName"] = "NetworkAddress",
                ["ClientDomainName"] = "NetworkAddress",
                ["Mac"] = "NetworkAddress",
                ["ServerUri"] = "ApplicationUri",
                ["ApplicationUri"] = "ApplicationUri",
                ["AppUri"] = "ApplicationUri",
                ["User"] = "UserIdentity",
                ["UserName"] = "UserIdentity",
                ["Identity"] = "UserIdentity"
            };

        /// <summary>
        /// Deliberate exceptions: "file name|method|parameter" with the
        /// class the parameter carries instead of the default one.
        /// </summary>
        private static readonly Dictionary<string, string> s_overrides =
            new(StringComparer.Ordinal)
            {
                // The registration key of the LDS store is the ServerUri.
                ["RegisteredServerStore.cs|LdsRemovedRegistration|uri"] = "ApplicationUri"
            };

        private static readonly Regex s_loggerMessage = new(
            @"\[LoggerMessage\s*\((?<args>.*?)\)\]\s*(?:\[[^\]]*\]\s*)*" +
            @"(?:public|internal|private)[^;{]*?\b(?<name>\w+)\s*\((?<params>[^;{]*?)\)\s*;",
            RegexOptions.Singleline | RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(10));

        private static readonly Regex s_literal = new(
            "\"((?:[^\"\\\\]|\\\\.)*)\"",
            RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(10));

        private static readonly Regex s_placeholder = new(
            @"\{(?<name>[A-Za-z_][A-Za-z0-9_]*)(?::[^}]*)?\}",
            RegexOptions.CultureInvariant,
            TimeSpan.FromSeconds(10));

        [Test]
        public void SensitiveLogParametersAreClassified()
        {
            string src = FindSourceRoot();
            var missing = new List<string>();
            int classified = 0;
            foreach (string file in EnumerateSources(src))
            {
                string text = File.ReadAllText(file);
                foreach (Match message in s_loggerMessage.Matches(text))
                {
                    foreach ((string parameter, string expected) in SensitiveParameters(message))
                    {
                        string key = Path.GetFileName(file) + "|" +
                            message.Groups["name"].Value + "|" + ParameterName(parameter);
                        string required = s_overrides.TryGetValue(key, out string? o) ? o : expected;
                        if (Regex.IsMatch(
                            parameter,
                            @"\[\s*" + required + @"(Attribute)?\s*\]",
                            RegexOptions.CultureInvariant,
                            TimeSpan.FromSeconds(10)))
                        {
                            classified++;
                        }
                        else
                        {
                            missing.Add(
                                Path.GetRelativePath(src, file) + ": " +
                                message.Groups["name"].Value + "(" + parameter.Trim() +
                                ") needs [" + required + "]");
                        }
                    }
                }
            }

            Assert.That(missing, Is.Empty, string.Join(Environment.NewLine, missing));
            // Sanity check that the scan found the annotated messages at all.
            Assert.That(classified, Is.GreaterThan(100));
        }

        [Test]
        public void ProjectsWithClassifiedLogParametersUseTheExtendedGenerator()
        {
            string src = FindSourceRoot();
            var missing = new List<string>();
            foreach (string project in Directory.EnumerateFiles(
                src, "*.csproj", SearchOption.AllDirectories))
            {
                string directory = Path.GetDirectoryName(project)!;
                bool usesClassification = EnumerateSources(directory).Any(file =>
                    s_loggerMessage.Matches(File.ReadAllText(file)).Any(m =>
                        Regex.IsMatch(
                            m.Groups["params"].Value,
                            @"\[\s*(NetworkAddress|ApplicationUri|UserIdentity)(Attribute)?\s*\]",
                            RegexOptions.CultureInvariant,
                            TimeSpan.FromSeconds(10))));
                if (usesClassification &&
                    !File.ReadAllText(project).Contains(
                        "\"Microsoft.Extensions.Telemetry.Abstractions\"",
                        StringComparison.Ordinal))
                {
                    missing.Add(Path.GetFileName(project));
                }
            }

            // Without the extended generator the attributes are ignored and
            // the values are logged unclassified.
            Assert.That(missing, Is.Empty, string.Join(Environment.NewLine, missing));
        }

        /// <summary>
        /// Files that log classified values through a logger created
        /// elsewhere, with where that logger is wrapped.
        /// </summary>
        private static readonly Dictionary<string, string> s_wrappedElsewhere =
            new(StringComparer.Ordinal)
            {
                ["DiscoveryClient.cs"] = "ClientBase",
                ["ApplicationsNodeManager.AliasNames.cs"] = "ApplicationsNodeManager.cs",
                ["GlobalDiscoverySampleServer.cs"] = "ServerBase",
                ["OpenUsdConnector.Composition.cs"] = "OpenUsdConnector.cs",
                ["RealTimeChannelLease.cs"] = "UaRobotIntentTransport.Logger",
                ["ReverseConnectServer.cs"] = "ServerBase",
                ["StandardServer.cs"] = "ServerBase"
            };

        [Test]
        public void CallersOfClassifiedMessagesUseAClassifiedLogger()
        {
            string src = FindSourceRoot();
            var methods = new HashSet<string>(StringComparer.Ordinal);
            foreach (string file in EnumerateSources(src))
            {
                foreach (Match message in s_loggerMessage.Matches(File.ReadAllText(file)))
                {
                    if (Regex.IsMatch(
                        message.Groups["params"].Value,
                        @"\[\s*(NetworkAddress|ApplicationUri|UserIdentity)(Attribute)?\s*\]",
                        RegexOptions.CultureInvariant,
                        TimeSpan.FromSeconds(10)))
                    {
                        methods.Add(message.Groups["name"].Value);
                    }
                }
            }
            var call = new Regex(
                @"\.(" + string.Join("|", methods) + @")\(",
                RegexOptions.CultureInvariant,
                TimeSpan.FromSeconds(10));
            var missing = new List<string>();
            foreach (string file in EnumerateSources(src))
            {
                string text = File.ReadAllText(file);
                if (call.IsMatch(text) &&
                    !text.Contains("CreateClassifiedLogger", StringComparison.Ordinal) &&
                    !text.Contains("WithClassifiedPassThrough", StringComparison.Ordinal) &&
                    !s_wrappedElsewhere.ContainsKey(Path.GetFileName(file)))
                {
                    missing.Add(Path.GetRelativePath(src, file));
                }
            }

            // A logger that is not wrapped prints "(null)" for classified
            // values unless redaction is enabled.
            Assert.That(methods, Has.Count.GreaterThan(100));
            Assert.That(missing, Is.Empty, string.Join(Environment.NewLine, missing));
        }

        private static IEnumerable<(string Parameter, string Classification)> SensitiveParameters(
            Match message)
        {
            string args = message.Groups["args"].Value;
            int index = args.IndexOf("Message", StringComparison.Ordinal);
            if (index < 0)
            {
                yield break;
            }
            string template = string.Concat(
                s_literal.Matches(args[index..]).Select(m => m.Groups[1].Value));
            var wanted = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (Match placeholder in s_placeholder.Matches(template))
            {
                if (s_sensitivePlaceholders.TryGetValue(
                    placeholder.Groups["name"].Value,
                    out string? classification))
                {
                    wanted[placeholder.Groups["name"].Value] = classification;
                }
            }
            if (wanted.Count == 0)
            {
                yield break;
            }
            foreach (string parameter in SplitParameters(message.Groups["params"].Value))
            {
                if (wanted.TryGetValue(ParameterName(parameter), out string? classification))
                {
                    yield return (parameter, classification);
                }
            }
        }

        private static string ParameterName(string parameter)
        {
            string declaration = parameter.Split('=')[0].Trim();
            int space = declaration.LastIndexOfAny([' ', '\t', '\n', '\r']);
            return space < 0 ? declaration : declaration[(space + 1)..];
        }

        private static IEnumerable<string> SplitParameters(string parameters)
        {
            int depth = 0;
            int start = 0;
            for (int ii = 0; ii < parameters.Length; ii++)
            {
                switch (parameters[ii])
                {
                    case '<' or '(' or '[':
                        depth++;
                        break;
                    case '>' or ')' or ']':
                        depth--;
                        break;
                    case ',' when depth == 0:
                        yield return parameters[start..ii];
                        start = ii + 1;
                        break;
                }
            }
            yield return parameters[start..];
        }

        private static IEnumerable<string> EnumerateSources(string directory)
        {
            char separator = Path.DirectorySeparatorChar;
            return Directory
                .EnumerateFiles(directory, "*.cs", SearchOption.AllDirectories)
                .Where(f =>
                    !f.Contains(separator + "obj" + separator, StringComparison.Ordinal) &&
                    !f.Contains(separator + "bin" + separator, StringComparison.Ordinal));
        }

        private static string FindSourceRoot()
        {
            string? directory = Path.GetDirectoryName(
                typeof(ClassifiedLogMessageGuardTests).Assembly.Location);
            while (!string.IsNullOrEmpty(directory))
            {
                if (File.Exists(Path.Combine(directory, "UA.slnx")))
                {
                    return Path.Combine(directory, "src");
                }
                directory = Path.GetDirectoryName(directory);
            }
            Assert.Ignore("The source tree is not available next to the test assembly.");
            return string.Empty;
        }
    }
}
#endif
