import 'session_manager.dart';

/// ============================================================
///  معترض المصادقة — يربط الجلسة الواحدة بطبقة الشبكة.
///  1) يُرفق التوكن الحالي مع كل طلب.
///  2) عند 401 (توكن باطل = طُرد الجهاز) ينهي الجلسة محلياً فوراً.
///
///  مبني على واجهة عامة ليعمل مع أي عميل HTTP (dio/http).
/// ============================================================

class AuthInterceptor {
  AuthInterceptor(this._session);

  final SessionManager _session;

  /// يُدعى قبل إرسال الطلب: يضيف ترويسة المصادقة.
  Map<String, String> applyHeaders(Map<String, String> headers) {
    final token = _session.currentToken;
    if (token != null) {
      headers['Authorization'] = 'Bearer $token';
      // ترويسة إضافية اختيارية للخادم لمطابقة الجلسة الواحدة صراحةً.
      headers['X-Session-Token'] = token;
    }
    return headers;
  }

  /// يُدعى بعد استلام الرد: يفحص حالة الطرد.
  /// أعد true إذا عولجت الحالة (طرد) ويجب إيقاف السلسلة.
  Future<bool> onResponse(int statusCode, {String? errorCode}) async {
    // 401 مع رمز الجلسة الباطلة = دخول من جهاز آخر.
    if (statusCode == 401 && (errorCode == 'session_superseded' || errorCode == null)) {
      await _session.handleUnauthorized();
      return true;
    }
    return false;
  }
}
