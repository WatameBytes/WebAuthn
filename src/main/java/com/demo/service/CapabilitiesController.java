package com.demo.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.Map;

@Slf4j
@RestController
@RequiredArgsConstructor
public class CapabilitiesController {

    private final ObjectMapper objectMapper;

    @PostMapping("/capabilities")
    public ResponseEntity<?> capture(@RequestBody Map<String, Object> body) {
        try {
            ObjectNode dump = objectMapper.createObjectNode();
            dump.put("timestamp", Instant.now().toString());
            dump.put("userAgent", (String) body.getOrDefault("userAgent", "unknown"));

            // capabilities is a flat map of String -> Boolean from the browser
            Object caps = body.get("capabilities");
            dump.set("capabilities", objectMapper.valueToTree(caps));

            writeDumpToFile(dump);

            log.info("[CAPABILITIES] {}", caps);

            return ResponseEntity.ok(Map.of("status", "ok"));
        } catch (Exception e) {
            log.error("Failed to capture capabilities", e);
            return ResponseEntity.internalServerError().body(Map.of("error", e.getMessage()));
        }
    }

    private void writeDumpToFile(ObjectNode dump) {
        try {
            String timestamp = Instant.now().toString().replace(":", "-").replace(".", "-");
            Path dumpFile = Path.of("capabilities-" + timestamp + ".json");
            String content = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(dump);
            Files.writeString(dumpFile, content, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            log.info("Capabilities written to {}", dumpFile.toAbsolutePath());
        } catch (IOException e) {
            log.error("Failed to write capabilities dump", e);
        }
    }
}

