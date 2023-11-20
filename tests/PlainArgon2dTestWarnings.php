<?php
/* MIT License (c) 2023 Identeco */

use PHPUnit\Framework\TestCase;

require __DIR__ . "/../PlainArgon2d.php";

class PlainArgon2dTestWarnings extends TestCase
{

    public function test_argon2d_with_iterations_1_warning()
    {
        $argon2 = new PlainArgon2d();
        $this->expectNotice();
        $this->expectNoticeMessage("To compute secure password hashes with one iteration, the memory should at least exceed 47104 KiB");
        $argon2->argon2d_raw_hash("password", "MyRandomNewSalt123" , 32, 1, 1, 32, 0x13);
    }

    public function test_argon2d_with_iterations_2_warning()
    {
        $argon2 = new PlainArgon2d();
        $this->expectNotice();
        $this->expectNoticeMessage("To compute secure password hashes with two iteration, the memory should at least exceed 19456 KiB");
        $argon2->argon2d_raw_hash("password", "MyRandomNewSalt123" , 32, 2, 1, 32, 0x13);
    }

    public function test_argon2d_with_iterations_3_warning()
    {
        $argon2 = new PlainArgon2d();
        $this->expectNotice();
        $this->expectNoticeMessage("To compute secure password hashes with three iteration, the memory should at least exceed 12288 KiB");
        $argon2->argon2d_raw_hash("password", "MyRandomNewSalt123" , 32, 3, 1, 32, 0x13);
    }

    public function test_argon2d_with_iterations_4_warning()
    {
        $argon2 = new PlainArgon2d();
        $this->expectNotice();
        $this->expectNoticeMessage("To compute secure password hashes with four iteration, the memory should at least exceed 9216 KiB");
        $argon2->argon2d_raw_hash("password", "MyRandomNewSalt123" , 32, 4, 1, 32, 0x13);
    }

    public function test_argon2d_with_iterations_5_warning()
    {
        $argon2 = new PlainArgon2d();
        $this->expectNotice();
        $this->expectNoticeMessage("To compute secure password hashes with five iteration, the memory should at least exceed 7168 KiB");
        $argon2->argon2d_raw_hash("password", "MyRandomNewSalt123" , 32, 5, 1, 32, 0x13);
    }

    public function test_argon2d_with_iterations_6_warning()
    {
        $argon2 = new PlainArgon2d();
        $this->expectNotice();
        $this->expectNoticeMessage("To compute secure password hashes with more then five iteration, the memory should at least exceed 7168 KiB");
        $argon2->argon2d_raw_hash("password", "MyRandomNewSalt123" , 32, 6, 1, 32, 0x13);
    }

}
?>
