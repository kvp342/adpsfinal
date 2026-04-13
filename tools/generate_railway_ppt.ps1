$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$csvPath = Join-Path $root "RAILWAY_PRESENTATION_SLIDES.csv"
$outPath = Join-Path $root "RAILWAY_PRESENTATION_SLIDES.pptx"

if (-not (Test-Path $csvPath)) {
  throw "CSV not found: $csvPath"
}

$rows = Import-Csv -Path $csvPath

$ppt = New-Object -ComObject PowerPoint.Application

$pres = $ppt.Presentations.Add()

$ppLayoutText = 2
$msoTrue = -1
$msoFalse = 0

$i = 1
foreach ($r in $rows) {
  $title = [string]$r.Title
  $bullets = @()
  1..6 | ForEach-Object {
    $v = [string]$r."Bullet $_"
    if ($v -and $v.Trim().Length -gt 0) { $bullets += $v.Trim() }
  }
  $notes = [string]$r."Speaker Notes"

  $slide = $pres.Slides.Add($i, $ppLayoutText)
  $i++

  $slide.Shapes.Title.TextFrame.TextRange.Text = $title

  $body = $slide.Shapes.Placeholders(2).TextFrame.TextRange
  $body.Text = ($bullets -join "`r`n")
  if ($bullets.Count -gt 0) {
    $body.ParagraphFormat.Bullet.Visible = $msoTrue
  } else {
    $body.ParagraphFormat.Bullet.Visible = $msoFalse
  }

  if ($notes -and $notes.Trim().Length -gt 0) {
    $notesShape = $slide.NotesPage.Shapes.Placeholders(2)
    $notesShape.TextFrame.TextRange.Text = $notes
  }
}

if (Test-Path $outPath) { Remove-Item -Force $outPath }
$pres.SaveAs($outPath)
$pres.Close()
$ppt.Quit()

Set-Content -Path (Join-Path $root "RAILWAY_PPT_GENERATION_MARKER.txt") -Value $outPath -Encoding UTF8
Write-Output "Wrote: $outPath"

