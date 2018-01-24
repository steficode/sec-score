package com.cloudera.fce.security.secscore.output;

import com.cloudera.fce.security.secscore.dto.Result;
import com.cloudera.fce.security.secscore.dto.ResultsSummary;
import com.fasterxml.jackson.databind.SequenceWriter;
import com.fasterxml.jackson.dataformat.csv.CsvMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.util.List;

public class CsvOutputWriter {

    private static final Logger LOG = LogManager.getLogger(CsvOutputWriter.class);

    public void write(List<ResultsSummary> resultsSummaryList, File outputFile) throws IOException {
        LOG.info("Writing CSV results to location: {}", outputFile);
        CsvMapper mapper = new CsvMapper();
        SequenceWriter writer = mapper.writer(CsvOutputLine.getCsvSchema()).writeValues(outputFile);
        for (ResultsSummary resultsSummary: resultsSummaryList) {
            for (Result result: resultsSummary.getResultList()) {
                writer.write(new CsvOutputLine(resultsSummary, result));
            }
        }
    }

}
