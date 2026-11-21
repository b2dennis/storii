package sh.base2.storii.core

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/** A value a secret had before it was changed. */
@Serializable
data class HistoryEntry(val field: String, val value: String, @SerialName("changed_at") val changedAt: String)

/** Password history, as internal/vault/history.go (shared cases: testdata/history.json). */
object PasswordHistory {
    const val MAX = 10
    val FIELDS = listOf("password", "key")

    /** [next] as it should be stored when it replaces [prev]: the history always comes from prev, and each history
     *  field whose value changed adds prev's value in front. [now] is an ISO time without fractions. */
    fun apply(prev: Item, next: Item, now: String): Item {
        val h = prev.history.toMutableList()
        if (prev.isSecret) {
            for (f in FIELDS.reversed()) {
                val old = prev.fields[f].orEmpty()
                if (old.isNotEmpty() && old != next.fields[f]) h.add(0, HistoryEntry(f, old, now))
            }
        }
        return next.copy(history = h.take(MAX))
    }
}
