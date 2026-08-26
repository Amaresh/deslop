
@Composable
fun InboxPane() {
    LaunchedEffect(Unit) { mailbox.fetch() }
}
