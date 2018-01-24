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

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class ResultsSummary implements Serializable {
    private static final long serialVersionUID = -1684765015468256905L;
    private List<Result> resultList;
    private int totalScore;
    private int maximumScore;
    private boolean hasFatalFailures = false;
    private String clusterName;
    private String clusterDisplayName;
    private String version;
    private String fullVersion;
    private String customerId;
    private String deploymentTimestamp;

    public String getCustomerId() {
        return customerId;
    }

    public void setCustomerId(String customerId) {
        this.customerId = customerId;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    private String fileName;

    public ResultsSummary() {
        resultList = new ArrayList<Result>(200);
    }

    public List<Result> getResultList() {
        return resultList;
    }

    public int getTotalScore() {
        return totalScore;
    }

    public int getMaximumScore() {
        return maximumScore;
    }

    public void addResult(Result res) {
        resultList.add(res);
        maximumScore += res.getScore();
        if (res.isPass()) {
            totalScore += res.getScore();
        } else if (res.isFatal()) {
            hasFatalFailures = true;
        }
    }

    public String getPercentage() {
        return ((int)((totalScore * 100.0f) / (maximumScore))) + "%";
    }

    public float getPassRateFloat() {
        return (totalScore * 100.0f) / maximumScore;
    }

    public int getExecutedResultsCount() {
        return resultList.size();
    }

    public String getClusterName() {
        return clusterName;
    }

    public void setClusterName(String clusterName) {
        this.clusterName = clusterName;
    }

    public String getClusterDisplayName() {
        return clusterDisplayName;
    }

    public void setClusterDisplayName(String clusterDisplayName) {
        this.clusterDisplayName = clusterDisplayName;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getFullVersion() {
        return fullVersion;
    }

    public void setFullVersion(String fullVersion) {
        this.fullVersion = fullVersion;
    }

    public String getDeploymentTimestamp() {
        return deploymentTimestamp;
    }

    public void setDeploymentTimestamp(String deploymentTimestamp) {
        this.deploymentTimestamp = deploymentTimestamp;
    }
}
