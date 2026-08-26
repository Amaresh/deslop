
class InboxViewModel : ViewModel() {
    fun refresh() {
        viewModelScope.launch { mailbox.sync() }
    }
}
