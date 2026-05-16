from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .models import XSSEvent

@api_view(['POST'])
def ingest_event(request):
    data = request.data
    required = ['sessionId', 'timestamp', 'label', 'probability', 'features', 'latencyMs']
    for field in required:
        if field not in data:
            return Response({'error': f'Missing field: {field}'}, status=status.HTTP_400_BAD_REQUEST)

    if data['label'] not in ['malicious', 'benign']:
        return Response({'error': 'label must be malicious or benign'}, status=status.HTTP_400_BAD_REQUEST)

    if not (0 <= data['probability'] <= 1):
        return Response({'error': 'probability out of range'}, status=status.HTTP_400_BAD_REQUEST)

    XSSEvent.objects.create(
        session_id=data['sessionId'],
        timestamp=data['timestamp'],
        label=data['label'],
        probability=data['probability'],
        features=data['features'],
        latency_ms=data['latencyMs']
    )
    return Response({'ok': True}, status=status.HTTP_201_CREATED)


@api_view(['GET'])
def list_events(request):
    events = XSSEvent.objects.all()[:200]
    data = [{
        'id': e.id,
        'session_id': e.session_id,
        'label': e.label,
        'probability': e.probability,
        'latency_ms': e.latency_ms,
        'created_at': e.created_at.isoformat(),
    } for e in events]
    return Response(data)
