package com.cloudera.fce.security.secscore.output;

import com.cloudera.fce.security.secscore.dto.Result;
import com.cloudera.fce.security.secscore.dto.ResultsSummary;
import com.fasterxml.jackson.dataformat.csv.CsvSchema;

class CsvOutputLine {

    private final ResultsSummary resultsSummary;
    private final Result result;

    CsvOutputLine(final ResultsSummary resultsSummary, final Result result) {
        this.resultsSummary = resultsSummary;
        this.result = result;
    }

    public String getClusterName() {
        return resultsSummary.getClusterName();
    }

    public String getClusterDisplayName() {
        return resultsSummary.getClusterDisplayName();
    }

    public String getDescription() {
        return result.getDescription();
    }

    public boolean isFatal() {
        return result.isFatal();
    }

    public int getLevel() {
        return result.getLevel();
    }

    public String getMessage() {
        return result.getMessage();
    }

    public boolean isPass() {
        return result.isPass();
    }

    public int getScore() {
        return result.getScore();
    }

    public String getService() {
        return result.getService();
    }

    public static CsvSchema getCsvSchema() {
        return CsvSchema.builder()
                .setUseHeader(true)
                .addColumn("clusterName")
                .addColumn("clusterDisplayName")
                .addColumn("service")
                .addColumn("description")
                .addNumberColumn("level")
                .addNumberColumn("score")
                .addBooleanColumn("pass")
                .addBooleanColumn("fatal")
                .addColumn("message")
                .build();
    }


}
