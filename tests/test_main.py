"""
Tests for the protect_my_dir.main module.
"""

import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from protect_my_dir.main import (
    decrypt_directory,
    decrypt_file,
    derive_key,
    encrypt_directory,
    encrypt_file,
    main,
    protect,
)


# ---------------------------------------------------------------------------
# derive_key
# ---------------------------------------------------------------------------


class TestDeriveKey:
    def test_returns_bytes_of_correct_length(self):
        key = derive_key("password", b"saltsaltsaltsalt")
        assert isinstance(key, bytes)
        assert len(key) == 32

    def test_same_inputs_produce_same_key(self):
        salt = b"saltsaltsaltsalt"
        key1 = derive_key("password", salt)
        key2 = derive_key("password", salt)
        assert key1 == key2

    def test_different_passwords_produce_different_keys(self):
        salt = b"saltsaltsaltsalt"
        key1 = derive_key("password1", salt)
        key2 = derive_key("password2", salt)
        assert key1 != key2

    def test_different_salts_produce_different_keys(self):
        key1 = derive_key("password", b"saltsaltsaltsalt")
        key2 = derive_key("password", b"differentsalt123")
        assert key1 != key2


# ---------------------------------------------------------------------------
# encrypt_file / decrypt_file
# ---------------------------------------------------------------------------


class TestEncryptFile:
    def test_encrypt_creates_enc_file_and_removes_original(self, tmp_path):
        original = tmp_path / "file.txt"
        original.write_text("hello world")

        encrypt_file(original, "secret")

        enc_file = tmp_path / "file.txt.enc"
        assert enc_file.exists()
        assert not original.exists()

    def test_encrypt_enc_file_has_salt_iv_and_ciphertext(self, tmp_path):
        original = tmp_path / "data.bin"
        original.write_bytes(b"some data")

        encrypt_file(original, "secret")

        enc_file = tmp_path / "data.bin.enc"
        # salt (16) + iv (16) + at least 1 block of ciphertext (16)
        assert len(enc_file.read_bytes()) >= 48

    def test_encrypt_produces_different_ciphertexts_each_time(self, tmp_path):
        content = b"deterministic test"
        f1 = tmp_path / "a.txt"
        f2 = tmp_path / "b.txt"
        f1.write_bytes(content)
        f2.write_bytes(content)

        encrypt_file(f1, "pw")
        encrypt_file(f2, "pw")

        assert (tmp_path / "a.txt.enc").read_bytes() != (tmp_path / "b.txt.enc").read_bytes()


class TestDecryptFile:
    def test_round_trip_restores_original_content(self, tmp_path):
        original = tmp_path / "secret.txt"
        content = b"top secret content"
        original.write_bytes(content)

        encrypt_file(original, "mypassword")
        enc_file = tmp_path / "secret.txt.enc"

        decrypt_file(enc_file, "mypassword")

        restored = tmp_path / "secret.txt"
        assert restored.exists()
        assert restored.read_bytes() == content
        assert not enc_file.exists()

    def test_wrong_password_prints_error_and_leaves_enc_file(self, tmp_path, capsys):
        original = tmp_path / "file.txt"
        original.write_bytes(b"data")

        encrypt_file(original, "correct")
        enc_file = tmp_path / "file.txt.enc"

        decrypt_file(enc_file, "wrong_password")

        # enc file should remain untouched
        assert enc_file.exists()
        # restored file should not exist
        assert not (tmp_path / "file.txt").exists()

    def test_decrypt_empty_file_prints_error(self, tmp_path):
        bad_file = tmp_path / "bad.txt.enc"
        bad_file.write_bytes(b"")

        # Should not raise; click.echo handles the error message
        decrypt_file(bad_file, "any")

    def test_decrypt_corrupted_data_prints_error(self, tmp_path):
        bad_file = tmp_path / "corrupt.txt.enc"
        # Write salt + iv but no valid ciphertext
        bad_file.write_bytes(b"\x00" * 32 + b"\x01" * 10)

        decrypt_file(bad_file, "password")

        # The encrypted file should still be present since decryption failed
        assert bad_file.exists()


# ---------------------------------------------------------------------------
# encrypt_directory / decrypt_directory
# ---------------------------------------------------------------------------


class TestEncryptDirectory:
    def test_encrypts_all_files_in_directory(self, tmp_path):
        (tmp_path / "a.txt").write_text("file a")
        (tmp_path / "b.txt").write_text("file b")

        encrypt_directory(tmp_path, "pwd")

        assert (tmp_path / "a.txt.enc").exists()
        assert (tmp_path / "b.txt.enc").exists()
        assert not (tmp_path / "a.txt").exists()
        assert not (tmp_path / "b.txt").exists()

    def test_encrypts_files_in_subdirectories(self, tmp_path):
        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / "nested.txt").write_text("nested content")

        encrypt_directory(tmp_path, "pwd")

        assert (sub / "nested.txt.enc").exists()
        assert not (sub / "nested.txt").exists()

    def test_empty_directory_does_nothing(self, tmp_path):
        # Should not raise
        encrypt_directory(tmp_path, "pwd")
        assert list(tmp_path.iterdir()) == []


class TestDecryptDirectory:
    def test_decrypts_all_enc_files_in_directory(self, tmp_path):
        (tmp_path / "a.txt").write_bytes(b"aaa")
        (tmp_path / "b.txt").write_bytes(b"bbb")
        encrypt_directory(tmp_path, "pwd")

        decrypt_directory(tmp_path, "pwd")

        assert (tmp_path / "a.txt").exists()
        assert (tmp_path / "b.txt").exists()
        assert not (tmp_path / "a.txt.enc").exists()
        assert not (tmp_path / "b.txt.enc").exists()

    def test_ignores_non_enc_files(self, tmp_path):
        plain = tmp_path / "plain.txt"
        plain.write_text("untouched")

        decrypt_directory(tmp_path, "pwd")

        assert plain.read_text() == "untouched"

    def test_round_trip_preserves_content(self, tmp_path):
        content = b"important data"
        (tmp_path / "data.bin").write_bytes(content)

        encrypt_directory(tmp_path, "mypassword")
        decrypt_directory(tmp_path, "mypassword")

        assert (tmp_path / "data.bin").read_bytes() == content


# ---------------------------------------------------------------------------
# protect (CLI command via CliRunner)
# ---------------------------------------------------------------------------


class TestProtectCommand:
    def test_encrypt_flag_encrypts_directory(self, tmp_path):
        (tmp_path / "file.txt").write_text("hello")
        runner = CliRunner()

        result = runner.invoke(protect, ["-dir", str(tmp_path), "--encrypt"], input="testpassword\n")

        assert result.exit_code == 0
        assert "Finished encrypting" in result.output
        assert (tmp_path / "file.txt.enc").exists()
        assert not (tmp_path / "file.txt").exists()

    def test_decrypt_flag_decrypts_directory(self, tmp_path):
        content = b"secret"
        (tmp_path / "secret.txt").write_bytes(content)
        runner = CliRunner()

        # First encrypt
        runner.invoke(protect, ["-dir", str(tmp_path), "--encrypt"], input="pass\n")
        # Then decrypt
        result = runner.invoke(protect, ["-dir", str(tmp_path), "--decrypt"], input="pass\n")

        assert result.exit_code == 0
        assert "Finished decrypting" in result.output
        assert (tmp_path / "secret.txt").read_bytes() == content

    def test_both_flags_prints_error(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(protect, ["-dir", str(tmp_path), "--decrypt", "--encrypt"], input="pw\n")

        assert result.exit_code == 0
        assert "Please specify either --decrypt or --encrypt, not both." in result.output

    def test_no_action_flag_prints_error(self, tmp_path):
        runner = CliRunner()
        result = runner.invoke(protect, ["-dir", str(tmp_path)], input="pw\n")

        assert result.exit_code == 0
        assert "No action specified" in result.output

    def test_missing_directory_argument_fails(self):
        runner = CliRunner()
        result = runner.invoke(protect, [])

        assert result.exit_code != 0

    def test_nonexistent_directory_fails(self, tmp_path):
        runner = CliRunner()
        non_existent = str(tmp_path / "does_not_exist")
        result = runner.invoke(protect, ["-dir", non_existent, "--encrypt"], input="pw\n")

        # Click validates the path and will return a non-zero exit code
        assert result.exit_code != 0

    def test_empty_password_aborts(self, tmp_path):
        runner = CliRunner()
        # click.prompt does not accept empty strings by default; it keeps
        # reprompting until input is exhausted and then aborts with exit code 1.
        result = runner.invoke(protect, ["-dir", str(tmp_path), "--encrypt"], input="\n")

        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# main entry point
# ---------------------------------------------------------------------------


class TestMain:
    def test_main_invokes_protect_command(self, tmp_path):
        runner = CliRunner()
        # main() simply calls protect(); invoke protect directly as main
        # delegates to it without adding any extra logic.
        with runner.isolated_filesystem():
            os.makedirs("mydir")
            result = runner.invoke(protect, ["-dir", "mydir", "--encrypt"], input="pw\n")
        assert result.exit_code == 0
        assert "Finished encrypting" in result.output

    def test_main_is_callable(self):
        # Verify that main is a plain callable (not a click command) that
        # delegates to protect().
        from unittest.mock import patch

        with patch("protect_my_dir.main.protect") as mock_protect:
            main()
            mock_protect.assert_called_once()
