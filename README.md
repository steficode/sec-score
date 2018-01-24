# sec-score

Basic idea is to be able to automate a security rating based on a cluster configuration dump.

To be used as an FCE asset in the new “Security Healthcheck” PS offering

Provide a score by evaluating a set of rules against:
Deployment JSON
(Optionally) Security Inspector Results

## Usage

### Clone the repo:
http://github.mtv.cloudera.com/tristan/sec-score.git

### Build using maven:
mvn install

### Usage:
    usage: default
     -c,--outputcsvfile <arg>      If specified will generate an output CSV
                                   file
     -d,--deploymentjson <arg>     JSON file acquired from
                                   http(s)://cmhost:718[03]api/v12/cm/deployme
                                   nt?view=EXPORT_REDACTED
     -h,--outputhtmlfile <arg>     If specified will generate an output HTML
                                   file
     -l,--offline                  If specified will embed all the CSS and JS
                                   dependencies statically in HTML output.
                                   This will make the HTML larger by viewable
                                   without access to the Internet. By default
                                   the HTML output will include references to
                                   online dependencies.
     -n,--clustername <arg>        If specified will selected a specific
                                   cluster from the JSON by name
     -o,--outputfile <arg>         Name of the results file to be output
     -r,--rulesjson <arg>          JSON file containing the ruleset
     -s,--secinspectorjson <arg>   JSON results from running the Security
                                   Inspector
     -v,--verbose                  If specified will output logs at DEBUG
                                   level
     -vv,--trace                   If specified will output logs at TRACE
                                   level. This is a large amount of output.
     -x,--outputxmlfile <arg>      If specified will save the intermediate XML
                                   file (for testing)


### Run using the examples provided:
    java -jar target/sec-score-0.3-SNAPSHOT-jar-with-dependencies.jar --deploymentjson src/test/resources/configs/nightly/nightly-redacted.json --outputfile results.json

## Developers' Guide
The basic design of the code is as follows:
  1. Read Deployment JSON and Security Inspector JSON from the files provided on the command line.
  2. Use Jackson to read the JSON in.
  3. Use Jackson data bindings to write the JSON out as XML.
  4. Concatenate the XML together into one super XML.
  5. (Optionally write the XML out to file for debugging purposes).
  6. Read the XML in using Saxon-HE.
  7. Read the rules.json file into POJOs (using Jackson).
  8. For each rule that was in the JSON, run the XPath using Saxon and store the results in a POJO.
  9. Persist the results to a file.

### Resources
XML/XPath development tooling:
XMLSpear: An XML Editor for Mac OS X.
http://www.donkeydevelopment.com/#downloads
Allows visual XPath development/debugging

PathEnq: Online XPath development/visualisation:
http://www.qutoric.com/xslt/analyser/xpathtool.html
Includes ‘trace’ mode, which will highlight results as you type XPath expression

Cheat Sheets: 
https://gist.github.com/LeCoupa/8c305ec8c713aad07b14 
https://www.cheatography.com/alexsiminiuc/cheat-sheets/xpath/pdf/ 

### Example Rule:
    {
      "preConditionXPath": "/Security/deployment/ObjectNode/clusters/services[type='HUE']",
      "ruleXPath": "/Security/deployment/ObjectNode/clusters/services[type='HUE']//items[name='ssl_enable']/value='true'",
      "level": 1,
      "description": "Hue TLS",
      "fatal": false,
      "passMessage": "Hue is configured to use TLS",
      "errorMessage": "Hue is not configured for TLS (HTTPS)",
      "score": 1
    }

### Rules Development
The master rules list is at https://docs.google.com/a/cloudera.com/spreadsheets/d/1NkL7xtQ8S0lXgvmW4Qw1BTNjIvn4goHZZ-vyP9NItd8/edit?usp=sharing

The process for developing rules is as follows:
  1. Choose a rule.
  2. Assign it to yourself in the GSheet
  3. Develop and test it (+ve and -ve cases).
  4. Once you are happy, add it to default-rules.json
  5. Commit back to here.
  
### Logging
This application is configured to log via log4j2. By default the sole logger (com.cloudera.fce.security) will output to stdout at INFO. Further logs are available at DEBUG and TRACE, accessible with the -verbose and -trace flags respectively.
