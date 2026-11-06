package sh.base2.storii.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val Light = lightColorScheme(
    primary = Color(0xFF5856D6), onPrimary = Color.White,
    primaryContainer = Color(0xFFE3E1FF), onPrimaryContainer = Color(0xFF16135F),
    secondary = Color(0xFF5D5C72), tertiary = Color(0xFF7A5367),
    background = Color(0xFFF8F7FC), surface = Color(0xFFF8F7FC),
    surfaceContainer = Color(0xFFEFEEF5), surfaceContainerHigh = Color(0xFFE9E8F0),
)
private val Dark = darkColorScheme(
    primary = Color(0xFFC3C0FF), onPrimary = Color(0xFF2A2690),
    primaryContainer = Color(0xFF413EBA), onPrimaryContainer = Color(0xFFE3E1FF),
    secondary = Color(0xFFC6C4DD), tertiary = Color(0xFFE9B9D0),
    background = Color(0xFF131318), surface = Color(0xFF131318),
    surfaceContainer = Color(0xFF1F1F25), surfaceContainerHigh = Color(0xFF2A292F),
)

@Composable
fun StoriiTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = if (isSystemInDarkTheme()) Dark else Light, content = content)
}
