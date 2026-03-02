package main

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"github.com/artilugio0/seshador"
)

const (
	defaultVaultURL = "https://h7b3lcyzrrjhylfjvcno2cr3xa0azkvb.lambda-url.us-east-1.on.aws"
)

func main() {
	a := app.New()
	w := a.NewWindow("seshador – Secure Secret Sharing")

	shareBtn := widget.NewButton("I want to share a Secret", func() {
		showShareUI(w)
	})
	receiveBtn := widget.NewButton("I want to receive a Secret", func() {
		showReceiveFlow(w)
	})

	buttons := container.NewHBox(
		shareBtn,
		layout.NewSpacer(),
		receiveBtn,
	)

	content := container.NewVBox(
		buttons,
	)

	w.SetContent(container.NewCenter(content))
	w.ShowAndRun()
}

func showShareUI(parent fyne.Window) {
	vaultEntry := widget.NewEntry()
	vaultEntry.SetPlaceHolder("Leave empty to use default public vault")

	receiverCode := widget.NewEntry()
	receiverCode.SetPlaceHolder("Paste the code the receiver sent you")

	secretEntry := widget.NewMultiLineEntry()
	secretEntry.SetPlaceHolder("Secret to share")

	ownerCodeEntry := widget.NewEntry()
	ownerCodeEntry.Hide()

	result := widget.NewLabel("Send this code to the receiver:")
	result.Hide()

	copyToClipboardButton := widget.NewButton("Copy to clipboard", func() {
		parent.Clipboard().SetContent(ownerCodeEntry.Text)
	})
	copyToClipboardButton.Hide()

	vaultURLInput := container.NewVBox(
		widget.NewLabel("Vault URL"),
		vaultEntry,
	)
	vaultURLInput.Hide()
	defaultVaultURLCheck := widget.NewCheck("Use default public vault", func(enabled bool) {
		if !enabled {
			vaultURLInput.Show()
			return
		}
		vaultURLInput.Hide()
	})
	defaultVaultURLCheck.Checked = true

	var shareButton *widget.Button
	shareButton = widget.NewButton("Share", func() {
		code := strings.TrimSpace(receiverCode.Text)
		if code == "" {
			dialog.ShowError(fmt.Errorf("receiver code is required"), parent)
			return
		}

		secret := strings.TrimSpace(secretEntry.Text)
		if secret == "" {
			dialog.ShowError(fmt.Errorf("secret is required"), parent)
			return
		}

		msg, err := base64.URLEncoding.DecodeString(code)
		if err != nil {
			dialog.ShowError(fmt.Errorf("invalid receiver code: %v", err), parent)
			return
		}

		dhPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
		owner := seshador.NewOwner(dhPriv)

		if err := owner.ProcessReceiverMessage(msg); err != nil {
			dialog.ShowError(err, parent)
			return
		}

		vaultURL := defaultVaultURL
		if !defaultVaultURLCheck.Checked {
			if vaultEntry.Text == "" {
				dialog.ShowError(errors.New("please specify the Vault URL or use the default value"), parent)
				return
			}
			vaultURL = vaultEntry.Text
		}

		vClient := seshador.NewVaultClientHTTP(vaultURL)
		if err := owner.StoreSecret([]byte(secret), vClient); err != nil {
			dialog.ShowError(err, parent)
			return
		}

		toSend := owner.MessageToReceiver()

		ownerCodeEntry.Text = base64.URLEncoding.EncodeToString(toSend)
		vaultEntry.Disable()
		secretEntry.Disable()
		shareButton.Disable()
		receiverCode.Disable()
		result.Show()
		ownerCodeEntry.Show()
		copyToClipboardButton.Show()
	})

	form := container.NewVBox(
		vaultURLInput,
		defaultVaultURLCheck,
		widget.NewLabel("Receiver's initial code"), receiverCode,
		widget.NewLabel("Secret"), secretEntry,
		shareButton,
		result,
		ownerCodeEntry,
		copyToClipboardButton,
	)

	d := dialog.NewCustom("Share", "Back", form, parent)
	d.Resize(fyne.NewSize(520, 480))
	d.Show()
}

func showReceiveFlow(parent fyne.Window) {
	dhPriv, _ := ecdh.X25519().GenerateKey(rand.Reader)
	_, sigPriv, _ := ed25519.GenerateKey(rand.Reader)
	receiver := seshador.NewReceiver(dhPriv, sigPriv)

	initialMsg := receiver.InitialMessage()
	initialB64 := base64.URLEncoding.EncodeToString(initialMsg)

	receiverCodeEntry := widget.NewEntry()
	receiverCodeEntry.Text = initialB64

	var step1 *fyne.Container
	var step2 *fyne.Container
	nextBtn := widget.NewButton("Next", func() {
		step1.Hide()
		step2.Show()
	})

	vaultEntry := widget.NewEntry()
	vaultURLInput := container.NewVBox(
		widget.NewLabel("Vault URL"),
		vaultEntry,
	)
	vaultURLInput.Hide()
	defaultVaultURLCheck := widget.NewCheck("Use default public vault", func(enabled bool) {
		if !enabled {
			vaultURLInput.Show()
			return
		}
		vaultURLInput.Hide()
	})
	defaultVaultURLCheck.Checked = true

	ownerCode := widget.NewEntry()
	ownerCode.SetPlaceHolder("Paste the code the owner sent you")

	result := widget.NewLabel("Secret received:")
	result.Hide()
	secretEntry := widget.NewMultiLineEntry()
	secretEntry.Hide()

	copyToClipboardButton := widget.NewButton("Copy to clipboard", func() {
		parent.Clipboard().SetContent(secretEntry.Text)
	})
	copyToClipboardButton.Hide()

	btn := widget.NewButton("Retrieve Secret", func() {
		code := strings.TrimSpace(ownerCode.Text)
		if code == "" {
			dialog.ShowError(fmt.Errorf("code is required"), parent)
			return
		}

		msg, err := base64.URLEncoding.DecodeString(code)
		if err != nil {
			dialog.ShowError(fmt.Errorf("invalid code format: %v", err), parent)
			return
		}

		if err := receiver.ProcessOwnerMessage(msg); err != nil {
			dialog.ShowError(err, parent)
			return
		}

		vaultURL := defaultVaultURL
		if !defaultVaultURLCheck.Checked {
			if vaultEntry.Text == "" {
				dialog.ShowError(errors.New("please specify the Vault URL or use the default value"), parent)
				return
			}
			vaultURL = vaultEntry.Text
		}

		vClient := seshador.NewVaultClientHTTP(vaultURL)
		secret, err := receiver.RetrieveSecret(vClient)
		if err != nil {
			dialog.ShowError(err, parent)
			return
		}

		secretEntry.Text = string(secret)

		result.Show()
		secretEntry.Show()
		copyToClipboardButton.Show()
	})

	step1 = container.NewVBox(
		widget.NewLabel("Send this code to the owner (this is NOT secret — anyone can see it)"),
		receiverCodeEntry,
		widget.NewButton("Copy to clipboard", func() {
			parent.Clipboard().SetContent(receiverCodeEntry.Text)
		}),
		layout.NewSpacer(),
		nextBtn,
	)

	step2 = container.NewVBox(
		vaultURLInput,
		defaultVaultURLCheck,
		widget.NewLabel("Paste the code from the owner"),
		ownerCode,
		btn,
		result,
		secretEntry,
		copyToClipboardButton,
	)
	step2.Hide()

	content := container.NewVBox(
		step1,
		step2,
	)

	d := dialog.NewCustom("Receive", "Back", content, parent)
	d.Resize(fyne.NewSize(520, 520))
	d.Show()
}
