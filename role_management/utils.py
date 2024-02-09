from django.http import JsonResponse

def sendResponse(code, message, data=None):
    return JsonResponse({'code': code, 'message': message, 'data': data})

