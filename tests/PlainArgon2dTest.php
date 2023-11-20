<?php
/* MIT License (c) 2023 Identeco */

use PHPUnit\Framework\TestCase;

require __DIR__ . "/../PlainArgon2d.php";

class PlainArgon2dTest extends TestCase
{
    public function test_argon2_version_constants()
    {
        $argon2 = new PlainArgon2d();
        $this->assertEquals(0x10, VERSION_10);
        $this->assertEquals(0x13, VERSION_13);
        $this->assertEquals(0, DEFAULT_VALUE);
    }

    public function test_argon2d_with_rfc()
    {
        error_reporting(0);
        $argon2 = new PlainArgon2d();
        $password=hex2bin("0101010101010101010101010101010101010101010101010101010101010101");
        $salt=hex2bin("02020202020202020202020202020202");
        $secret_key=hex2bin("0303030303030303");
        $ad=hex2bin("040404040404040404040404");
        $hash=bin2hex($argon2->argon2d_raw_hash($password, $salt , 32, 3, 4, 32, 0x13, $secret_key , $ad));
        $this->assertEquals("512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb", $hash);
    }

    public function test_argon2d_for_credential_check()
    {
        error_reporting(0);
        $argon2 = new PlainArgon2d();
        $hash=bin2hex($argon2->argon2d_raw_hash("test@example.com", "StaticSalt" , 512, 1, 1, 32, 0x13));
        $this->assertEquals("e2a8f54c300962421342d44ed2ad2924fd34024720136367e10ae58bc86676b8", $hash);
    }

    public function test_argon2d_without_parameters()
    {
        error_reporting(0);
        $argon2 = new PlainArgon2d();
        $hash=bin2hex($argon2->argon2d_raw_hash("password", "RandomSalt"));
        $this->assertEquals("93b8814c592dcc33123105074346a802121fa5bff52c6c56d7a399fbad4c9755", $hash);
    }

    public function test_argon2d_versions()
    {
        error_reporting(0);
        $argon2 = new PlainArgon2d();
        $hash=bin2hex($argon2->argon2d_raw_hash("password", "RandomSalt" , 512, 3, 4, 32, 0x13));
        $this->assertEquals("71bcbf7638796c436b7cb12841fc24f2b907f9c41c7fb25a47172441e1a05247", $hash);
        $hash=bin2hex($argon2->argon2d_raw_hash("password", "RandomSalt" , 512, 3, 4, 32, 0x10));
        $this->assertEquals("3f2d8b86294f09f756c8c5703a529f20f09743640fd5e70a65d6dcf26834d639", $hash);
    }

    public function test_argon2d_tag_length()
    {
        error_reporting(0);
        $argon2 = new PlainArgon2d();
        $hash=bin2hex($argon2->argon2d_raw_hash("password", "RandomSalt" , 32, 3, 4, 66, 0x13));
        $this->assertEquals("1b4ed672f850762b63e306504eb9c507ddeb11df71db4956eafdc045eef1816d3c01903c54985a8f8c17f23ba5f5d350675d4a91db68a12ab45858768c50d0e03b1d", $hash);
        $hash=bin2hex($argon2->argon2d_raw_hash("password", "RandomSalt" , 32, 3, 4, 6, 0x10));
        $this->assertEquals("e916d8faea83", $hash);
    }

    public function test_argon2d_default_parameter()
    {
        error_reporting(0);
        $argon2 = new PlainArgon2d();
        $hash=bin2hex($argon2->argon2d_raw_hash("password", "RandomSalt",DEFAULT_VALUE,DEFAULT_VALUE,DEFAULT_VALUE,DEFAULT_VALUE,DEFAULT_VALUE));
        $this->assertEquals("93b8814c592dcc33123105074346a802121fa5bff52c6c56d7a399fbad4c9755", $hash);
    }

    public function test_argon2d_with_salt_exception()
    {
        error_reporting(0);
        $argon2 = new PlainArgon2d();
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("Salt must be in the value range from 8 to 2^32-1 bytes");
        $argon2->argon2d_raw_hash("password", "short" , 32, 3, 4, 32, 0x13);
    }
    public function test_argon2d_with_memory_exception()
    {
        error_reporting(0);
        $argon2 = new PlainArgon2d();
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("Memory must be in the value range from (8*parallelism) to 2^32-1");
        $argon2->argon2d_raw_hash("password", "123456789" , -1, 3, 4, 32, 0x13);
    }

    public function test_argon2d_with_iterations_exception()
    {
        error_reporting(0);
        $argon2 = new PlainArgon2d();
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("Iterations must be in the value range from 1 to 2^32-1");
        $argon2->argon2d_raw_hash("password", "123456789" , 32, -1, 4, 32, 0x13);
    }

    public function test_argon2d_with_parallelism_exception()
    {
        error_reporting(0);
        $argon2 = new PlainArgon2d();
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("Parallelism must be in the value range from 1 to 2^24-1");
        $argon2->argon2d_raw_hash("password", "123456789" , 32, 3, -1, 32, 0x13);
    }

    public function test_argon2d_with_tag_length_exception()
    {
        error_reporting(0);
        $argon2 = new PlainArgon2d();
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("Tag length must be in the value range from 4 to 2^32-1 bytes");
        $argon2->argon2d_raw_hash("password", "123456789" , 32, 3, 4, 1, 0x13);
    }

    public function test_argon2d_with_version_exception()
    {
        error_reporting(0);
        $argon2 = new PlainArgon2d();
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage("Version must be VERSION_13 or VERSION_10");
        $argon2->argon2d_raw_hash("password", "123456789" , 32, 3, 4, 32, 0x1);
    }

}
?>
