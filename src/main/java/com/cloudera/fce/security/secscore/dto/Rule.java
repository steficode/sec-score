package com.cloudera.fce.security.secscore.dto;
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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.io.Serializable;
import java.util.List;

@JsonIgnoreProperties(value = { "_comment" })
public class Rule implements Serializable {
    private static final long serialVersionUID = 7261111362701130420L;
    private String preConditionXPath;
    private String ruleXPath;
    private int level;
    private String description;
    private String service;
    private boolean fatal;
    private String errorMessage;
    private String passMessage;
    private String documentation;
    private int score;
    private boolean failOnTrue = false;
    private int id;
    private List<String> categories;
    private List<String> outputXPaths;

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getPassMessage() {
        return passMessage;
    }

    public void setPassMessage(String passMessage) {
        this.passMessage = passMessage;
    }

    public boolean isFailOnTrue() {
        return failOnTrue;
    }

    public void setFailOnTrue(boolean failOnTrue) {
        this.failOnTrue = failOnTrue;
    }

    public int getScore() {
        return score;
    }

    public void setScore(int score) {
        this.score = score;
    }

    public String getPreConditionXPath() {
        return preConditionXPath;
    }

    public void setPreConditionXPath(String preConditionXPath) {
        this.preConditionXPath = preConditionXPath;
    }

    public String getRuleXPath() {
        return ruleXPath;
    }

    public void setRuleXPath(String ruleXPath) {
        this.ruleXPath = ruleXPath;
    }

    public int getLevel() {
        return level;
    }

    public void setLevel(int level) {
        this.level = level;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getService() {
        return service;
    }

    public void setService(String service) {
        this.service = service;
    }

    public boolean isFatal() {
        return fatal;
    }

    public void setFatal(boolean fatal) {
        this.fatal = fatal;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public void setCategories(List<String> categories) {
        this.categories = categories;
    }

    public List<String> getCategories() {
        return categories;
    }

    public String getDocumentation() {
        return documentation;
    }

    public void setDocumentation(String documentation) {
        this.documentation = documentation;
    }

    public List<String> getOutputXPaths() {
        return outputXPaths;
    }

    public void setOutputXPaths(List<String> outputXpaths) {
        this.outputXPaths = outputXpaths;
    }
}
