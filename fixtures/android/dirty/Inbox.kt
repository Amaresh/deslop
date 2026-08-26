
@Composable
fun InboxPane() {
    val mail = runBlocking { mailbox.fetch() }
    Text(mail.subject)
}
