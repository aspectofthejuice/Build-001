Add-Type -AssemblyName System.Windows.Forms
[System.Windows.Forms.Application]::EnableVisualStyles()

# Read users from Condition.txt
$users = @()
Get-Content ".\Condition.txt" | ForEach-Object {
    $parts = $_.Split(',')
    if ($parts.Count -ge 1) {
        $users += [PSCustomObject]@{
            Name = $parts[0].Trim()
            Level = if ($parts.Count -ge 2) { $parts[1].Trim() } else { "user" }
            Password = ""
        }
    }
}

# Create form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Set Passwords for Users"
$form.Size = New-Object System.Drawing.Size(400, ($users.Count * 35 + 80))
$form.StartPosition = "CenterScreen"

$y = 10
$textboxes = @()
foreach ($user in $users) {
    $label = New-Object System.Windows.Forms.Label
    $label.Text = "$($user.Name) ($($user.Level))"
    $label.Location = New-Object System.Drawing.Point(10, $y)
    $label.Size = New-Object System.Drawing.Size(150, 20)
    $form.Controls.Add($label)

    $textbox = New-Object System.Windows.Forms.TextBox
    $textbox.Location = New-Object System.Drawing.Point(170, $y)
    $textbox.Size = New-Object System.Drawing.Size(200, 20)
    $textbox.UseSystemPasswordChar = $true
    $form.Controls.Add($textbox)
    $textboxes += $textbox

    $y += 30
}

$okButton = New-Object System.Windows.Forms.Button
$okButton.Text = "Apply"
$okButton.Location = New-Object System.Drawing.Point(150, $y)
$okButton.Add_Click({
    for ($i=0; $i -lt $users.Count; $i++) {
        $users[$i].Password = $textboxes[$i].Text
    }
    $form.Close()
})
$form.Controls.Add($okButton)

$form.ShowDialog()

# Save passwords to JSON
$users | ConvertTo-Json | Out-File ".\passwords.json" -Force
