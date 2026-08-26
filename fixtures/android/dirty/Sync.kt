
class SyncReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        GlobalScope.launch { uploader.flush() }
    }
}
