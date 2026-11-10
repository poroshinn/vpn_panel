"""SSH-слой панели (FR-3.1.x): пул соединений, TOFU known-hosts, circuit breaker, пробы.

Единственное место в проекте, где допустимы импорты ``paramiko``
(ADR-0002); наружу — только async-API.
"""
