"""Static validation fixture for background work, timing, and messaging."""

import asyncio

from celery import shared_task
from kafka import KafkaProducer


@shared_task
async def publish_results(records):
    producer = KafkaProducer()
    for record in records:
        await asyncio.sleep(0)
        producer.send("results", record)
    return len(records)
