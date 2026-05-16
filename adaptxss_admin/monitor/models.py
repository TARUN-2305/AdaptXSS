from django.db import models

class XSSEvent(models.Model):
    session_id   = models.CharField(max_length=64, db_index=True)
    timestamp    = models.BigIntegerField()
    label        = models.CharField(max_length=16)  # 'malicious' or 'benign'
    probability  = models.FloatField()
    features     = models.JSONField()
    latency_ms   = models.FloatField()
    created_at   = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'XSS Event'

    def __str__(self):
        return f"[{self.label.upper()}] {self.session_id[:12]} — prob={self.probability:.3f}"
