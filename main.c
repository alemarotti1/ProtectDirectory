#include <gpg-error.h>
#include <gpgme.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

int check_errors(gpg_error_t /* pointer to unsigned int*/ err) {
  if (err) {
    printf("\n");
    printf(gpgme_strerror(err));
    printf("\n");
    return err;
  }
  return 0;
}

static gpgme_error_t passphrase_callback(void *hook, const char *uid_hint,
                                         const char *passphrase_info,
                                         int prev_was_bad, int fd) {
  const char *passphrase = hook;

  if (prev_was_bad)
    return gpgme_error(GPG_ERR_BAD_PASSPHRASE);

  const gpgme_error_t error1 =
      gpgme_io_writen(fd, passphrase, strlen(passphrase));
  if (error1 < 0)
    return gpgme_error_from_errno(error1);

  const gpgme_error_t error2 =
      gpgme_io_writen(fd, passphrase, strlen(passphrase));
  if (gpgme_io_writen(fd, "\n", 1) < 0)
    return gpgme_error_from_errno(error2);

  return 0;
}

char *encryptText(char *message, char *password, gpg_error_t *err,
                  size_t *len) {
  gpgme_ctx_t ctx;
  gpgme_data_t plaintext;
  gpgme_data_t encryptedText;

  // this command is needed to start the gpgme library
  // otherwise the gpgme_new command will return
  // "GPG_ERR_NOT_OPERATIONAL"(or 176 in int)
  gpgme_check_version(NULL);

  *err = gpgme_new(&ctx);
  if (check_errors(*err)) {
    return NULL;
  }
  printf("gpgme iniciado com sucesso.\n");

  *err = gpgme_set_protocol(ctx, GPGME_PROTOCOL_OPENPGP);
  if (check_errors(*err)) {
    return NULL;
  }
  printf("protocolo setado com sucesso.\n");

  gpgme_set_passphrase_cb(ctx, passphrase_callback, (void *)password);

  // converts the "message" variable into the plaintext variable
  *err = gpgme_data_new_from_mem(&plaintext, message, strlen(message), 0);
  if (check_errors(*err)) {
    return NULL;
  }
  printf("mensagem salva com sucesso\n");

  /* creates an output data object */
  *err = gpgme_data_new(&encryptedText);
  if (check_errors(*err)) {
    return NULL;
  }
  printf("output criado\n");

  // This function is used to set the pinentry mode to loopback.
  //  If this is not set, the program will return an "operation cancelled" error
  *err = gpgme_set_pinentry_mode(ctx, GPGME_PINENTRY_MODE_LOOPBACK);
  if (check_errors(*err)) {
    return NULL;
  }

  // encrypts the text
  *err = gpgme_op_encrypt(ctx, NULL, GPGME_ENCRYPT_ALWAYS_TRUST, plaintext,
                          encryptedText);
  if (check_errors(*err)) {
    return NULL;
  }
  printf("texto criptografado\n");

  // gets the encrypted text
  char *encrypted = gpgme_data_release_and_get_mem(encryptedText, len);
}

int main(void) {
  gpg_error_t err;
  size_t len;

  char *encrypted = encryptText("oi", "senha", &err, &len);

  if (encrypted) {
    printf("Encrypted data (%zu bytes):\n", len);
    fwrite(encrypted, 1, len, stdout);
    printf("\n");

    gpgme_free(encrypted);
  }
  return 0;
}
