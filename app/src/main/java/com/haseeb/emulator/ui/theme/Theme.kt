package com.haseeb.emulator.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.unit.dp

private val HaseebDarkColorScheme = darkColorScheme(
    primary = TealAccent,
    onPrimary = OnTealAccent,
    primaryContainer = TealContainer,
    onPrimaryContainer = TealAccentBright,
    secondary = CyanHighlight,
    onSecondary = ObsidianBg,
    secondaryContainer = GlassSurfaceElevated,
    onSecondaryContainer = TextPrimary,
    tertiary = MagiskEmerald,
    background = ObsidianBg,
    onBackground = TextPrimary,
    surface = ObsidianSurface,
    onSurface = TextPrimary,
    surfaceVariant = GlassSurface,
    onSurfaceVariant = TextSecondary,
    outline = GlassBorderSubtle,
    outlineVariant = GlassBorderTeal,
    error = ErrorCoral,
    onError = TextPrimary,
    errorContainer = ErrorContainerDark,
    onErrorContainer = ErrorCoral,
)

private val HaseebShapes = Shapes(
    small = RoundedCornerShape(10.dp),
    medium = RoundedCornerShape(16.dp),
    large = RoundedCornerShape(22.dp),
    extraLarge = RoundedCornerShape(28.dp),
)

@Composable
fun HaseebGamingTheme(
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = HaseebDarkColorScheme,
        typography = HaseebTypography,
        shapes = HaseebShapes,
        content = content,
    )
}
