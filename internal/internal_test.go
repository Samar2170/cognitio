package internal_test

// var passwordDecryptionKey []byte

// func TestSecurity(t *testing.T) {
// 	os.Setenv("PASSWORD_DECRYPTION_KEY", "12345678901234567890123456789012")
// 	defer os.Unsetenv("PASSWORD_DECRYPTION_KEY")
// 	passwordDecryptionKey = []byte(os.Getenv("PASSWORD_DECRYPTION_KEY"))
// 	password := "test"
// 	encryptedPassword := internal.EncryptPassword(password)
// 	t.Log("encryptedPassword: ", encryptedPassword)
// 	decryptedPassword, err := internal.DecryptPassword(encryptedPassword)
// 	t.Log("decryptedPassword: ", decryptedPassword)
// 	if err != nil {
// 		t.Error(err)
// 	}
// 	if decryptedPassword != password {
// 		t.Error("decrypted password is not equal to original password")
// 	}
// 	t.Log("TestSecurity passed")
// }
