#!/usr/bin/env bash
set -euo pipefail

KAFKA_BOOTSTRAP="${KAFKA_BOOTSTRAP_SERVERS:-localhost:9092}"
KAFKA_TOPICS_CMD="${KAFKA_TOPICS_CMD:-kafka-topics.sh}"

echo "Waiting for Kafka to be ready at ${KAFKA_BOOTSTRAP}..."
until ${KAFKA_TOPICS_CMD} --bootstrap-server "${KAFKA_BOOTSTRAP}" --list > /dev/null 2>&1; do
    echo "  Kafka not ready yet, retrying in 5s..."
    sleep 5
done
echo "Kafka is ready."

create_topic() {
    local topic="$1"
    local partitions="$2"
    local retention="${3:-}"

    echo "Creating topic: ${topic} (partitions=${partitions}, retention=${retention:-default})"

    local cmd="${KAFKA_TOPICS_CMD} --bootstrap-server ${KAFKA_BOOTSTRAP} --create --if-not-exists --topic ${topic} --partitions ${partitions} --replication-factor 1"

    if [[ -n "${retention}" ]]; then
        cmd="${cmd} --config retention.ms=${retention}"
    fi

    eval "${cmd}"
}

# raw-flows: 6 partitions, retention 1 hour (3600000 ms)
create_topic "raw-flows" 6 "3600000"

# parsed-flows: 12 partitions, retention 24 hours (86400000 ms)
create_topic "parsed-flows" 12 "86400000"

# enriched-flows: 12 partitions, retention 7 days (604800000 ms)
create_topic "enriched-flows" 12 "604800000"

# alerts: 3 partitions, retention 30 days (2592000000 ms)
create_topic "alerts" 3 "2592000000"

# model-feedback: 3 partitions, default retention
create_topic "model-feedback" 3

echo "All Kafka topics created successfully."
