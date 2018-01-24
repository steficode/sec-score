package com.cloudera.fce.security.secscore;

/*
* Licensed to Cloudera, Inc. under one
* or more contributor license agreements.  See the NOTICE file
* distributed with this work for additional information
* regarding copyright ownership.  Cloudera, Inc. licenses this file
* to you under the Apache License, Version 2.0 (the
* "License"); you may not use this file except in compliance
* with the License.  You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

import com.cloudera.fce.security.secscore.dto.Result;
import com.cloudera.fce.security.secscore.dto.ResultsSummary;
import com.cloudera.fce.security.secscore.dto.Rule;
import com.cloudera.fce.security.secscore.dto.RuleList;
import com.cloudera.fce.security.secscore.output.CsvOutputWriter;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.xml.XmlMapper;


import java.io.*;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.CodeSource;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import javax.xml.transform.stream.StreamSource;


import net.sf.saxon.s9api.DocumentBuilder;
import net.sf.saxon.s9api.Processor;
import net.sf.saxon.s9api.QName;
import net.sf.saxon.s9api.SaxonApiException;
import net.sf.saxon.s9api.WhitespaceStrippingPolicy;
import net.sf.saxon.s9api.XPathCompiler;
import net.sf.saxon.s9api.XPathSelector;
import net.sf.saxon.s9api.XdmAtomicValue;
import net.sf.saxon.s9api.XdmItem;
import net.sf.saxon.s9api.XdmNode;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.text.StrSubstitutor;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;


public final class SecScore {
    public static final String CLUSTER_NAME_VARIABLE = "clusterName";
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String TIMESTAMP_XPATH = "/Security/deployment/ObjectNode/timestamp";
    private static final String CLUSTER_DISPLAYNAME_XPATH =
            "/Security/deployment/ObjectNode/clusters[name=$clusterName]/displayName";
    private static final String CLUSTER_VERSION_XPATH =
            "/Security/deployment/ObjectNode/clusters[name=$clusterName]/version";
    private static final String CLUSTER_FULLVERSION_XPATH =
            "/Security/deployment/ObjectNode/clusters[name=$clusterName]/fullVersion";
    public static final String CLUSTER_LIST_XPATH =
            "/Security/deployment/ObjectNode/clusters[services/type='HDFS']/name";
    private static final Logger LOG = LogManager.getLogger(SecScore.class);

    private static RuleList defaultRuleList;

    private SecScore() {
        //Not called
    }

    public static void main(String[] args) throws Exception {
        Options options = buildCmdLineOptions();
        CommandLineParser parser = new DefaultParser();
        CommandLine cmd = null;
        try {
            cmd = parser.parse(options, args);
        } catch (Exception e) {
            HelpFormatter formatter = new HelpFormatter();
            formatter.printHelp("default", options);
            System.exit(1);
        }

        String deploymentFile = cmd.getOptionValue("deploymentjson");
        String secInspectorFile = cmd.getOptionValue("secinspectorjson");
        String xmlFile = cmd.getOptionValue("outputxmlfile");
        String csvFile = cmd.getOptionValue("outputcsvfile");
        String jsonOutputFile = cmd.getOptionValue("outputfile");
        String rulesFile = cmd.getOptionValue("rulesjson");
        String htmlOutputFile = cmd.getOptionValue("outputhtmlfile");
        String clusterName = cmd.getOptionValue("clustername");

        if (cmd.hasOption("verbose")) {
            increaseVerbosity(false);
        }
        if (cmd.hasOption("trace")) {
            increaseVerbosity(true);
        }

        File jsonFile = new File(deploymentFile);
        if (!jsonFile.exists()) {
            LOG.error("Deployment file '{}' does not exist", jsonFile);
            System.exit(1);
        }
        File[] jsonFiles = null;
        if (jsonFile.isFile()) {
            jsonFiles = new File[1];
            jsonFiles[0] = jsonFile;
        } else { /* parameter is directory */
            FilenameFilter jsonFilter = new FilenameFilter() {
                public boolean accept(File dir, String name) {
                    String lowercaseName = name.toLowerCase();
                    return lowercaseName.endsWith(".json");
                }
            };
            String[] jsonFileNames = jsonFile.list(jsonFilter);
            jsonFiles = new File[jsonFileNames.length];
            int idx = 0;
            for (String filename : jsonFileNames) {
                jsonFiles[idx] = new File(deploymentFile, filename);
                idx += 1;
            }
        }

        String[] deploymentJsons = new String[jsonFiles.length];
        int idx = 0;
        for (File file : jsonFiles) {
            deploymentJsons[idx] = FileUtils.readFileToString(file, Charset.defaultCharset());
            idx += 1;
        }

        String secInspectorJson = null;
        if (secInspectorFile != null) {
            secInspectorJson = FileUtils.readFileToString(new File(secInspectorFile),
                    Charset.defaultCharset());
        }
        File xmlOutputFile = null;
        if (xmlFile != null) {
            xmlOutputFile = new File(xmlFile);
        }
        File csvOutputFile = null;
        if (csvFile != null) {
            csvOutputFile = new File(csvFile);
        }

        RuleList rules;
        if (rulesFile != null) {
            rules = MAPPER.readValue(new File(rulesFile), RuleList.class);
            LOG.info("Proceeding with rule file discovered at location {}, containing {} rules",
                    rulesFile, rules.getRuleList().size());
        } else {
            rules = MAPPER.readValue(SecScore.class.getClassLoader().getResourceAsStream(
                    "default-rules.json"), RuleList.class);
            LOG.info("Proceeding with classpath rule file default-rules.json, containing {} rules",
                    rules.getRuleList().size());
        }

        List<ResultsSummary> resultsList = new ArrayList<ResultsSummary>();
        for (String deploymentJson : deploymentJsons) {
            List<ResultsSummary> results = getResultsSummary(deploymentJson, rules, clusterName,
                    secInspectorJson, xmlOutputFile, null);
            if (results != null) {
                resultsList.addAll(results);
            }
        }

        if (jsonOutputFile != null) {
            LOG.info("Writing JSON results to location: {}", jsonOutputFile);
            MAPPER.writerWithDefaultPrettyPrinter().writeValue(
                    new File(jsonOutputFile), resultsList);
        }

        if (csvOutputFile != null) {
            CsvOutputWriter csvOutputWriter = new CsvOutputWriter();
            csvOutputWriter.write(resultsList, csvOutputFile);
        }

        LOG.debug("Results of rule execution: {}",
                MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(resultsList));

        if (htmlOutputFile != null) {
            LOG.info("Writing HTML output to location: {}", htmlOutputFile);
            buildHtml(resultsList, new File(htmlOutputFile), cmd.hasOption("offline"));
        }

        if (jsonOutputFile == null && htmlOutputFile == null) {
            LOG.warn("No output files specified. Consider -outputfile -outputhtmlfile");
        }
    }

    public static void initDefaultRules() {
        try {
            defaultRuleList = MAPPER.readValue(
                    SecScore.class.getClassLoader()
                            .getResourceAsStream("default-rules.json"), RuleList.class);
        } catch (IOException e) {
            LOG.warn("Failed to initialise default ruleset", e);
        }
    }

    public static List<ResultsSummary> getResultsSummary(String deploymentJson, RuleList rules,
                                                         String clusterName,
                                                         String secInspectorJson,
                                                         File xmlOutputFile, String customerId)  {
        Processor proc = new Processor(false);
        try {
            XdmNode deploymentDoc = buildTestXml(deploymentJson, secInspectorJson, xmlOutputFile,
                    proc);

            return executeRules(deploymentDoc, rules, proc, clusterName, customerId);
        } catch (Exception e) {
            LOG.error("Exception whilst processing rules. Returning null.", e);
            return null;
        }
    }

    public static List<ResultsSummary> getResultsSummary(String deploymentJson, RuleList rules,
                                                         String clusterName,
                                                         String secInspectorJson,
                                                         String customerId) throws Exception {
        return getResultsSummary(deploymentJson, rules, clusterName, secInspectorJson, null,
                customerId);
    }

    public static XdmNode buildTestXml(String deploymentJson, String secInspectorJson, File xmlFile,
                                       Processor proc) throws Exception {
        XmlMapper xmlMapper = new XmlMapper();

        JsonNode deploymentNode = MAPPER.readTree(deploymentJson);

        String fullXML = "<Security><deployment>"
                + xmlMapper.writeValueAsString(deploymentNode) + "</deployment>";

        if (secInspectorJson != null) {
            fullXML = fullXML + "<sec-inspector>"
                    + xmlMapper.writeValueAsString(MAPPER.readTree(secInspectorJson))
                    + "</sec-inspector>";
        }

        fullXML = fullXML + "</Security>";

        fullXML = fixXmlIssues(fullXML);

        DocumentBuilder builder = proc.newDocumentBuilder();
        builder.setLineNumbering(true);
        builder.setWhitespaceStrippingPolicy(WhitespaceStrippingPolicy.ALL);

        if (xmlFile != null) {
            FileUtils.writeStringToFile(xmlFile, fullXML, Charset.defaultCharset());
        }

        StringReader sr = new StringReader(fullXML);
        StreamSource ss = new StreamSource(sr);
        return builder.build(ss);
    }

    static String fixXmlIssues(String xml) {
        //This is a bit of a hack, but basically we're trying to unescape any escaped XML
        // that makes its way in
        //With a further fudge to avoid =<replacement> which is used in LDAP strings.

        //Need to seriously comments this to sh*t - and add some unit tests for it
        return xml
                //Metrics safety valves have substitution variables. Kill all.
                .replaceAll(
                        "(<name>hadoop_metrics2_safety_valve</name><value>)[\\s\\S]*?(</value>)",
                        "$1$2")
                //N.B. This deliberately skips elements that start with a number,
                // in lieu of the more likely arithmetic checks.
                .replaceAll(
                        "(?:([^=:]|^))(&lt;)(/?[A-Za-z])", "$1<$3")
                .replaceAll("&lt;?[\\w.-]*?>", "")
                .replaceAll("&gt;", ">")
                .replaceAll("&#xd;", "")
                .replaceAll("(&lt;)(!---?[\\S\\s]*?-->)", "<$2")
                //This is to work around the <IfMod !something> problem
                .replaceAll(
                        "((<)|(&lt;))([\\w.-]*)( ![\\w.-_]*)(>)([\\s\\w.-/]+)"
                                + "((<)|(&lt;))(/[\\w.-]*>)", "<$4>$7<$11")
                //This is to work around an example placeholder http://<foo>:8888
                .replaceAll("(//)(<)([\\w.-]*>:)", "$1&lt;$3")
                // A strange person did this: <abc@def>. We change it to <abcdef/>
                .replaceAll("(<[\\w.-]*)@([\\w.-]*)(>)", "$1$2/$3")
                //Banner HTML is the source of many errors. Kill all.
                .replaceAll("(<name>banner_html</name><value>)[\\s\\S]*?(</value>)", "$1$2")
                .replaceAll("(<name>CUSTOM_BANNER_HTML</name><value>)[\\s\\S]*?(</value>)", "$1$2")
                //Flume agent is the source of many errors. Kill all.
                .replaceAll("(<name>agent_config_file</name><value>)[\\s\\S]*?(</value>)", "$1$2")
                //Morphlines is the source of many errors. Kill all.
                .replaceAll("(<name>agent_morphlines_conf_file</name><value>)[\\s\\S]*?(</value>)",
                        "$1$2")
                .replaceAll(
                        "(<name>agent_grok_dictionary_conf_file</name><value>)[\\s\\S]*?(</value>)",
                        "$1$2")
                .replaceAll("(<name>morphlines_conf_file</name><value>)[\\s\\S]*?(</value>)",
                        "$1$2")
                .replaceAll(
                        "(<name>alertpublisher_email_(header|footer)</name><value>)"
                                + "[\\s\\S]*?(</value>)", "$1$3")
                .replaceAll(
                        "(<name>smon_derived_configs_safety_valve</name><value>)"
                                + "[\\s\\S]*?(</value>)", "$1$2")
                .replaceAll("(<name>ldap_username_pattern</name><value>)[\\s\\S]*?(</value>)",
                        "$1$2")
                .replaceAll(
                        "(<name>sdc-security.policy_role_safety_valve</name><value>)"
                                + "[\\s\\S]*?(</value>)", "$1$2")
                .replaceAll("(<name>service_triggers</name><value>)[\\s\\S]*?(</value>)", "$1$2")
                //Remove Hue banner HTML
                .replaceAll("banner_top_html(\\s)?=(')?.*?('|</value>|\\n)", "$3")
                //Remove Hue banner HTML
                .replaceAll("login_splash_html(\\s)?=.*?('|</value>|\\n)", "$2")
                //workaround a specifc bug in CM redaction
                .replaceAll("(<[A-Za-z]* name=)(REDACTED)\\n", "$1\"$2\" />\n")
                //workaround any instances where the end of a safety valve gets chopped,
                // for some reason.
                .replaceAll("&lt;/value>", "</value>");
    }

    private static void buildHtml(List<ResultsSummary> results, File outputHtml, boolean offline)
            throws IOException {
        InputStream is = SecScore.class.getClassLoader().getResourceAsStream("template.html");
        String template = IOUtils.toString(is, "ascii");
        String resultStr = MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(results);

        Map<String, String> values = new HashMap<String, String>();
        values.put("results", resultStr);
        if (offline) {
            String dependenciesDirPath = outputHtml.getAbsolutePath().replace(".html", "")
                    .replace(".html", "") + "_files";
            String dependenciesDirName = dependenciesDirPath.substring(dependenciesDirPath
                    .lastIndexOf("/")+1);
            createDependenciesDir(dependenciesDirPath);
            values.put("dependencies", getOfflineDependencies().replace("{dependenciesDir}",
                    dependenciesDirName));
        } else {
            values.put("dependencies", getOnlineDependencies());
        }
        StrSubstitutor sub = new StrSubstitutor(values, "{", "}");

        FileWriter writer = new FileWriter(outputHtml);
        try {
            writer.write(sub.replace(template));
        } finally {
            writer.close();
        }
    }

    private static String getOnlineDependencies() throws IOException {
        InputStream is = SecScore.class.getClassLoader()
                .getResourceAsStream("online-dependencies.html");
        return IOUtils.toString(is, "ascii");
    }

    private static String getOfflineDependencies() throws IOException {
        InputStream is = SecScore.class.getClassLoader()
                .getResourceAsStream("offline-dependencies.html");
        return IOUtils.toString(is, "ascii");
    }

    private static void createDependenciesDir(String dependenciesDir)
            throws IOException, RuntimeException {
        String prefix = "html_files/";
        for (String resource : getResources(prefix)) {
            File file = new File(dependenciesDir + resource.substring(prefix.length()-1));
            if (resource.endsWith("/")) {
                file.mkdirs();
            } else {
                InputStream is = SecScore.class.getClassLoader().getResourceAsStream(resource);
                FileUtils.copyInputStreamToFile(is, file);
            }
        }
    }

    private static String[] getResources(String prefix) throws IOException, RuntimeException {
        ArrayList<String> resources = new ArrayList<String>();
        CodeSource src = SecScore.class.getProtectionDomain().getCodeSource();
        if (src != null) {
            URL jar = src.getLocation();
            ZipInputStream zip = new ZipInputStream(jar.openStream());
            while(true) {
                ZipEntry e = zip.getNextEntry();
                if (e == null) {
                    break;
                }
                String name = e.getName();
                if (name.startsWith(prefix) && !name.equals(prefix)) {
                    resources.add(name);
                }
            }
        } else {
            throw new RuntimeException("Could not list resources in JAR file.");
        }
        return resources.toArray(new String[resources.size()]);
    }

    public static List<ResultsSummary> executeRules(XdmNode document, RuleList rules,
            Processor proc, String specificClusterName, String customerId)
            throws SaxonApiException {
        XPathCompiler xpath = proc.newXPathCompiler();

        List<ResultsSummary> resultsList = new ArrayList<ResultsSummary>();

        XPathSelector clusterListXpath;
        if (specificClusterName == null) {
            clusterListXpath = xpath.compile(CLUSTER_LIST_XPATH).load();
        } else {
            clusterListXpath = xpath
                    .compile("/Security/deployment/ObjectNode/clusters/name[text()='"
                            + specificClusterName + "']").load();
        }
        clusterListXpath.setContextItem(document);

        String deploymentTimestamp = extractProperty(xpath, document, TIMESTAMP_XPATH);

        if (clusterListXpath.effectiveBooleanValue()) {
            xpath.declareVariable(new QName(CLUSTER_NAME_VARIABLE));
            for (XdmItem cluster : clusterListXpath) {
                ResultsSummary results = new ResultsSummary();
                results.setCustomerId(customerId);
                String clusterName = cluster.getStringValue();
                LOG.info("Processing cluster [{}]", clusterName);
                results.setClusterName(clusterName);
                results.setClusterDisplayName(extractClusterProperty(xpath, document, clusterName,
                        CLUSTER_DISPLAYNAME_XPATH));
                results.setFullVersion(extractClusterProperty(xpath, document, clusterName,
                        CLUSTER_FULLVERSION_XPATH));
                results.setVersion(extractClusterProperty(xpath, document, clusterName,
                        CLUSTER_VERSION_XPATH));
                results.setDeploymentTimestamp(deploymentTimestamp);
                for (Rule rule : rules.getRuleList()) {
                    Result result = executeRule(document, rule, xpath, clusterName);
                    if (result != null) {
                        results.addResult(result);
                    }
                }
                resultsList.add(results);
            }
        } else {
            LOG.warn("Cluster '" + specificClusterName
                    + "' not found in deployment info. Not running rules.");
        }
        return resultsList;
    }

    private static String extractProperty(XPathCompiler compiler, XdmNode document,
                                          String xpathString) {
        try {
            XPathSelector xPathSelector = compiler.compile(xpathString).load();
            xPathSelector.setContextItem(document);
            XdmItem result = xPathSelector.evaluateSingle();
            if (result == null) {
                return null;
            } else {
                return result.getStringValue();
            }
        } catch (SaxonApiException e) {
            LOG.error("Error extracting property {} ", e, xpathString);
            return null;
        }
    }

    private static String extractClusterProperty(XPathCompiler compiler, XdmNode document,
                                                 String clusterName, String xpathString) {
        try {
            XPathSelector xPathSelector = compiler.compile(xpathString).load();
            xPathSelector.setContextItem(document);
            xPathSelector.setVariable(new QName(CLUSTER_NAME_VARIABLE),
                    new XdmAtomicValue(clusterName));
            XdmItem result = xPathSelector.evaluateSingle();
            if (result==null) {
                return null;
            } else {
                return result.getStringValue();
            }
        } catch (SaxonApiException e) {
            LOG.error("Error extracting cluster property {} ", e, xpathString);
            return null;
        }
    }

    public static Result executeRule(XdmNode document, Rule rule, XPathCompiler xpath,
                                     String clusterName) {
        try {
            XPathSelector preCondition = null;
            if (rule.getPreConditionXPath() != null) {
                preCondition = xpath.compile(rule.getPreConditionXPath()).load();
                preCondition.setContextItem(document);
                preCondition.setVariable(new QName(CLUSTER_NAME_VARIABLE),
                        new XdmAtomicValue(clusterName));
                LOG.debug("Executing Precondition: {} as XPath: {}", rule.getDescription(),
                        rule.getPreConditionXPath());
            }
            if (preCondition == null || preCondition.effectiveBooleanValue()) {
                XPathSelector ruleXpath = xpath.compile(rule.getRuleXPath()).load();
                ruleXpath.setContextItem(document);
                ruleXpath.setVariable(new QName(CLUSTER_NAME_VARIABLE),
                        new XdmAtomicValue(clusterName));
                LOG.trace("Executing rule: {} as XPath: {}", rule.getDescription(),
                        rule.getRuleXPath());
                boolean resultPass = ruleXpath.effectiveBooleanValue() ^ rule.isFailOnTrue();

                List<String> resultStrings = new ArrayList<String>();

                resultStrings.add(extractXPathResult(ruleXpath));

                if (rule.getOutputXPaths() != null) {
                    for (String xpathString : rule.getOutputXPaths()) {
                        XPathSelector resultXPath = xpath.compile(xpathString).load();
                        resultXPath.setContextItem(document);
                        resultXPath.setVariable(new QName(CLUSTER_NAME_VARIABLE),
                                new XdmAtomicValue(clusterName));
                        LOG.trace("Executing substitution string XPath: {}", xpathString);
                        resultStrings.add(extractXPathResult(resultXPath));
                    }
                }

                return new Result(rule, resultPass, resultStrings.toArray(new String[1]));
            } else {
                LOG.trace("Rule '{}' precondition did not pass", rule.getDescription());
                return null;
            }
        } catch (Exception e) {
            LOG.error("Exception encountered executing individual rule: {}",
                    rule.getDescription());
            LOG.error("Exception: ", e);
        }
        return null;
    }

    private static String extractXPathResult(XPathSelector xpath) throws SaxonApiException {
        StringBuilder resultSb = new StringBuilder();

        if (xpath.effectiveBooleanValue()) {
            int i = 0;
            for (XdmItem node : xpath) {
                if (i++ > 0) {
                    resultSb.append(", ");
                }
                resultSb.append(node.getStringValue());
            }
        }
        return resultSb.toString();
    }

    private static Options buildCmdLineOptions() {
        Options options = new Options();
        options.addOption(Option.builder("d")
                .longOpt("deploymentjson")
                .desc("JSON file acquired from http(s)://cmhost:718[03]api"
                        + "/v12/cm/deployment?view=EXPORT_REDACTED")
                .hasArg(true)
                .required(true).build());
        options.addOption(Option.builder("s")
                .longOpt("secinspectorjson")
                .desc("JSON results from running the Security Inspector")
                .hasArg(true)
                .required(false).build());
        options.addOption(Option.builder("o")
                .longOpt("outputfile")
                .desc("Name of the results file to be output")
                .hasArg(true)
                .required(false).build());
        options.addOption(Option.builder("r")
                .longOpt("rulesjson")
                .desc("JSON file containing the ruleset")
                .hasArg(true)
                .required(false).build());
        options.addOption(Option.builder("x")
                .longOpt("outputxmlfile")
                .desc("If specified will save the intermediate XML file (for testing)")
                .hasArg(true)
                .required(false).build());
        options.addOption(Option.builder("h")
                .longOpt("outputhtmlfile")
                .desc("If specified will generate an output HTML file")
                .hasArg(true)
                .required(false).build());
        options.addOption(Option.builder("c")
                .longOpt("outputcsvfile")
                .desc("If specified will generate an output CSV file")
                .hasArg(true)
                .required(false).build());
        options.addOption(Option.builder("n")
                .longOpt("clustername")
                .desc("If specified will selected a specific cluster from the JSON by name")
                .hasArg(true)
                .required(false).build());
        options.addOption(Option.builder("v")
                .longOpt("verbose")
                .desc("If specified will output logs at DEBUG level")
                .hasArg(false)
                .required(false).build());
        options.addOption(Option.builder("vv")
                .longOpt("trace")
                .desc("If specified will output logs at TRACE level. "
                        + "This is a large amount of output.")
                .hasArg(false)
                .required(false).build());
        options.addOption(Option.builder("l")
                .longOpt("offline")
                .desc("If specified will embed all the CSS and JS dependencies statically"
                        + " in HTML output." +
                     " This will make the HTML larger by viewable without access to the Internet." +
                     " By default the HTML output will include references to online dependencies.")
                .hasArg(false)
                .required(false).build());
        return options;
    }

    private static void increaseVerbosity(boolean trace) {
        Level level = trace ? Level.TRACE : Level.DEBUG;
        LoggerContext ctx = (LoggerContext) LogManager.getContext(false);
        Configuration config = ctx.getConfiguration();
        LoggerConfig loggerConfig = config.getLoggerConfig(LogManager.ROOT_LOGGER_NAME);
        loggerConfig.setLevel(level);
        ctx.updateLoggers();
    }

    public static List<ResultsSummary> simpleGetResults(String deploymentJson, String customerId) {
        try {
            if (defaultRuleList == null) {
                initDefaultRules();
            }
            LOG.info("Processing customerId [{}]", customerId);
            return getResultsSummary(deploymentJson, defaultRuleList, null,
                    null, customerId);
        } catch (Exception e) {
            LOG.warn("Exception processing - returning empty results.", e);
            return null;
        }
    }

    public static RuleList getDefaultRuleList() {
        return defaultRuleList;
    }
}
