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

import org.apache.commons.codec.digest.DigestUtils;

import java.io.Serializable;
import java.text.MessageFormat;
import java.util.List;

public class Result implements Serializable {
    private static final long serialVersionUID = 3223092297918855189L;
    private boolean pass;
    private String description;
    private String service;
    private int level;
    private int score;
    private boolean isFatal;
    private String message;
    private String documentation;
    private int id;
    private List<String> categories;
    private String ruleSha1;
    private String ruleXpath;

    public Result(Rule rule, boolean result, String[] resultStrings) {
        description = rule.getDescription();
        service = rule.getService();
        level = rule.getLevel();
        score = rule.getScore();
        isFatal = rule.isFatal();
        documentation = rule.getDocumentation();
        pass = result;
        String resultMessage;
        if (result) {
            resultMessage = rule.getPassMessage();
        } else {
            resultMessage = rule.getErrorMessage();
        }
        message = MessageFormat.format(resultMessage, resultStrings);
        id = rule.getId();
        categories = rule.getCategories();
        ruleSha1 = DigestUtils.sha1Hex(rule.getRuleXPath());
        ruleXpath = rule.getRuleXPath();
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getMessage() {
        return message;
    }

    public String getDocumentation() {
        return documentation;
    }

    public boolean isFatal() {
        return isFatal;
    }

    public void setFatal(boolean fatal) {
        isFatal = fatal;
    }

    public int getScore() {
        return score;
    }

    public void setScore(int score) {
        this.score = score;
    }

    public boolean isPass() {
        return pass;
    }

    public void setPass(boolean pass) {
        this.pass = pass;
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

    public int getLevel() {
        return level;
    }

    public void setLevel(int level) {
        this.level = level;
    }

    public List<String> getCategories() {
        return categories;
    }

    public void setCategories(List<String> categories) {
        this.categories = categories;
    }

    public String getRuleSha1() {
        return ruleSha1;
    }

    public void setRuleSha1(String ruleSha1) {
        this.ruleSha1 = ruleSha1;
    }

    public String getRuleXpath() {
        return ruleXpath;
    }

    public void setRuleXpath(String ruleXpath) {
        this.ruleXpath = ruleXpath;
    }
}
