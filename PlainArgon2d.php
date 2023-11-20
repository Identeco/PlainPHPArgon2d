<?php
/* MIT License (c) 2023 Identeco */

include_once "ext/blake2b.php";

class PlainArgon2d extends blake2b
{

    private $blake;

    public function __construct()
    {
        // When creating the class, define the constants for the two Argon2 versions
        if (!defined("VERSION_10")) {
            define("VERSION_10", 0x10);
        }
        if (!defined("VERSION_13")) {
            define("VERSION_13", 0x13);
        }
        if (!defined("DEFAULT_VALUE")) {
            define("DEFAULT_VALUE", 0);
        }
        // Initialisation of the Blake2b class
        $this->blake = new Blake2b();
    }

    /**
     * Low level function that computes an Argon2d hash.
     * All parameters are flexible, as long as they are within the allowed range of values. 
     * If unsafe parameters are used, an E_Notice is thrown. 
     * On fatal errors, an exception is thrown and the calculation is aborted. 
     * The return of a hash is done in decimal encoding. 
     *
     * @param  string $password User password
     * @param  string $salt Random string for each password
     * @param  int $memory_kib Size of the memory in KiB for the calculation
     * @param  int $iterations Number of iterations
     * @param  int $parallelism The number of parallel calculations that can be performed at the same time
     * @param  int $tag_length Output size of the hash in bytes
     * @param  string $secret_key Secret key
     * @param  string $associated_data Related data
     * @return string Hash in decimal encoding
     */
    public function argon2d_raw_hash(string $password, string $salt, int $memory_kib = 65536, int $iterations = 3, int $parallelism = 4, int $tag_length = 32, int $version = 0x13, string $secret_key = "", string $associated_data = ""): string
    {
        // Check if the method is executed on a 64-bit PHP installation
        if (PHP_INT_SIZE !== 8) {
            throw new RuntimeException("Argon2d is supporting only for 64-Bit PHP installations");
        }

        // Set the default values if no optional parameters are set

        if ($iterations == 0) {
            $iterations = 3;
        }

        if ($parallelism == 0) {
            $parallelism = 4;
        }

        if ($memory_kib == 0) {
            $memory_kib = 65536;
        }

        if ($tag_length  == 0) {
            $tag_length = 32;
        }

        if ($version == 0) {
            $version = 0x13;
        }

        // Check if parameters are in the allowed value range and throw an exception if they are not

        if (strlen($password) < 0 || strlen($password) >= 0xFFFFFFFF) {
            throw new InvalidArgumentException("Password must be in the value range from 0 to 2^32-1 bytes");
        }

        if (strlen($salt) < 8 || strlen($password) >= 0xFFFFFFFF) {
            throw new InvalidArgumentException("Salt must be in the value range from 8 to 2^32-1 bytes");
        }

        if ($iterations < 1 || $iterations >= 0xFFFFFFFF) {
            throw new InvalidArgumentException("Iterations must be in the value range from 1 to 2^32-1");
        }

        if ($parallelism < 1 || $parallelism >= 0xFFFFFF) {
            throw new InvalidArgumentException("Parallelism must be in the value range from 1 to 2^24-1");
        }

        if ($memory_kib < (8 * $parallelism) || $memory_kib >= 0xFFFFFFFF) {
            throw new InvalidArgumentException("Memory must be in the value range from (8*parallelism) to 2^32-1");
        }

        if ($tag_length < 4 || $memory_kib >= 0xFFFFFFFF) {
            throw new InvalidArgumentException("Tag length must be in the value range from 4 to 2^32-1 bytes");
        }

        if (!($version == 0x13 || $version == 0x10)) {
            throw new InvalidArgumentException("Version must be VERSION_13 or VERSION_10");
        }

        if (isset($secret_key) && (strlen($secret_key) < 0 || strlen($secret_key) >= 0xFFFFFFFF)) {
            throw new InvalidArgumentException("Secret key length must be in the value range from 0 to 2^32-1 bytes");
        }

        if (isset($associated_data) && (strlen($associated_data) < 0 || strlen($associated_data) >= 0xFFFFFFFF)) {
            throw new InvalidArgumentException("Secret key length must be in the value range from 0 to 2^32-1 bytes");
        }

        // Check that no insecure password hashing parameters are used, and if they are, raise a warning

        if (strlen($salt) < 16) {
            trigger_error("For password hashing, the salt should be randomly chosen for each password with at least 16 bytes", E_USER_NOTICE);
        }

        if ($tag_length < 32) {
            trigger_error("For password hashing the tag length should be at least 32 bytes", E_USER_NOTICE);
        }

        if (isset($secret_key) && strlen($secret_key) < 14) {
            trigger_error("For password hashing the secret key should be at least 14 bytes", E_USER_NOTICE);
        }

        if ($iterations == 1 && $memory_kib < 47104) {
            trigger_error("To compute secure password hashes with one iteration, the memory should at least exceed 47104 KiB", E_USER_NOTICE);
        }

        if ($iterations == 2 && $memory_kib < 19456) {
            trigger_error("To compute secure password hashes with two iteration, the memory should at least exceed 19456 KiB", E_USER_NOTICE);
        }

        if ($iterations == 3 && $memory_kib < 12288) {
            trigger_error("To compute secure password hashes with three iteration, the memory should at least exceed 12288 KiB", E_USER_NOTICE);
        }

        if ($iterations == 4 && $memory_kib < 9216) {
            trigger_error("To compute secure password hashes with four iteration, the memory should at least exceed 9216 KiB", E_USER_NOTICE);
        }

        if ($iterations == 5 && $memory_kib < 7168) {
            trigger_error("To compute secure password hashes with five iteration, the memory should at least exceed 7168 KiB", E_USER_NOTICE);
        }

        if ($iterations >= 6 && $memory_kib < 7168) {
            trigger_error("To compute secure password hashes with more then five iteration, the memory should at least exceed 7168 KiB", E_USER_NOTICE);
        }

        // Calculate the initial hash H0
        $H_0 = $this->blake->hash($this->le32($parallelism) . $this->le32($tag_length) . $this->le32($memory_kib) . $this->le32($iterations) . $this->le32($version) . $this->le32(0) . $this->le32(strlen($password)) . $password . $this->le32(strlen($salt)) . $salt . $this->le32(strlen($secret_key)) . $secret_key . $this->le32(strlen($associated_data)) . $associated_data, 64);

        // Calculate the number of memory blocks of 1KiB each.
        $memory_blocks = (int)(4 * $parallelism * ((int)($memory_kib / (4 * $parallelism))));

        // Calculate the number of blocks per lane
        $q = (int)($memory_blocks / $parallelism);

        // Allocate a 2D array for the blocks
        $B = new SplFixedArray($parallelism);
        for ($i = 0; $i < $parallelism; $i++) {
            $B[$i] = new SplFixedArray($q);
        }

        // Fill the blocks of the first two lines with random data from the initial hash H0
        for ($i = 0; $i < $parallelism; $i++) {
            for ($j = 0; $j < 2; $j++) {
                $B[$i][$j] = $this->convert_string_block_to_int64_array($this->variable_length_hash_function($H_0 . $this->le32($j) . $this->le32($i), 1024));
            }
        }

        // Delete the initial hash H0 after the calculation to prevent garbage collector attacks
        // If the sodium extension is present, the hash is safely overwritten with zeros
        if (function_exists("sodium_memzero")) {
            sodium_memzero($H_0);
        } else {
            unset($H_0);
        }

        // Calculate all the missing blocks in the first iteration
        // The blocks are calculated in groups for each line
        for ($slice = 0; $slice < 4; $slice++) {
            for ($i = 0; $i < $parallelism; $i++) {
                for ($j = 0; $j < $q / 4; $j++) {
                    // Blocks of the first two lines have already been calculated
                    if ($slice == 0 && ($j == 0 || $j == 1)) {
                        continue;
                    }
                    $absolute_index = ($q / 4) * $slice + $j;
                    // Determine the position of the randomly selected block
                    $l = $this->getLane($B[$i][$absolute_index - 1], 0, $slice, $i, $parallelism);
                    $z = $this->getIndex($B[$i][$absolute_index - 1], $j, 0, $slice, ($q / 4), $l == $i);
                    // Calculate the new block with the compression function G
                    $B[$i][$absolute_index] = $this->G($B[$i][$absolute_index - 1], $B[$l][$z]);                }
            }
        }

        // If the number of iterations is > 1, calculate the blocks (t-1) again
        for ($passes = 1; $passes < $iterations; $passes++) {
            for ($slice = 0; $slice < 4; $slice++) {
                for ($i = 0; $i < $parallelism; $i++) {
                    for ($j = 0; $j < $q / 4; $j++) {
                        $absolute_index = ($q / 4) * $slice + $j;
                        if ($slice == 0 && $j == 0) {
                            // Determine the position of the randomly selected block for the blocks on the first column
                            $l = $this->getLane($B[$i][$q - 1], $passes, $slice, $i, $parallelism);;
                            $z = $this->getIndex($B[$i][$q - 1], $j, $passes, $slice, ($q / 4), $l == $i);
                            // If the version is 1.3, the current block does not need to be overwritten, but the new block must be combined with the previous one by xor 
                            if ($version === 0x13) {
                                $B[$i][0] = $this->xor_int_block_array($this->G($B[$i][$q - 1], $B[$l][$z]), $B[$i][0]);
                            } else {
                                $B[$i][0] = $this->G($B[$i][$q - 1], $B[$l][$z]);
                            }
                            continue;
                        }
                        // Determine the position of the randomly selected block for all blocks not on the first column
                        $l = $this->getLane($B[$i][$absolute_index - 1], $passes, $slice, $i, $parallelism);;
                        $z = $this->getIndex($B[$i][$absolute_index - 1], $j, $passes, $slice, ($q / 4), $l == $i);
                        // If the version is 1.3, the current block does not need to be overwritten, but the new block must be combined with the previous one by xor
                        if ($version === 0x13) {
                            $B[$i][$absolute_index] = $this->xor_int_block_array($this->G($B[$i][$absolute_index - 1], $B[$l][$z]), $B[$i][$absolute_index]);
                        } else {
                            $B[$i][$absolute_index] = $this->G($B[$i][$absolute_index - 1], $B[$l][$z]);
                        }
                    }
                }
            }
        }
        // After all t passes combine all blocks of the last column to one block and calculate the hash and return it as result
        $c = $B[0][$q - 1];
        for ($i = 1; $i < $parallelism; $i++) {
            $c = $this->xor_int_block_array($c, $B[$i][$q - 1]);
        }
        return $this->variable_length_hash_function($this->convert_int64_array_to_string($c), $tag_length);
    }

    /**
     * Return an unsigned 32-bit integer as byte string in little endian
     *
     * @param  int $num unsigned 32-bit integer
     * @return string unsigned 32-bit integer as byte string in little endian
     */
    protected function le32(int $num): string
    {
        return pack("V", $num);
    }

    /**
     * For Argon2d, determine the column of the randomly selected block for the compression function G for a given block based on its position
     *
     * @param SplFixedArray $block Block with 1-KiB random data in 128 64-bit integers
     * @param int $passes Current iteration round
     * @param int $slice Current group of the block
     * @param int $lane Current row of the block
     * @param int $parallelism Number of rows
     * @return int selected column
     */
    protected function getLane(SplFixedArray $block, int $passes, int $slice, int $lane, int $parallelism): int
    {
        if ($passes == 0 && $slice == 0) {
            return $lane;
        }
        return $block[0][0] % $parallelism;
    }

    /**
     * For Argon2d, determines the row of the randomly selected block for the compression function G based on the current position of the block and the selected column
     *
     * @param SplFixedArray $block Block with 1-KiB random data in 128 64-bit integers
     * @param int $index Current position of the block in the row
     * @param int $passes Current iteration round
     * @param int $slice Current group of the block
     * @param int $slice_length Size of a group
     * @param bool $sameLane Truth value whether the column of the randomly selected block corresponds to the current column
     * @return int selected row
     */

    protected function getIndex(SplFixedArray $block, int $index, int $passes, int $slice, int $slice_length, bool $sameLane): int
    {
        // Determine the number of blocks that can be currently referenced
        if ($passes == 0) {
            if ($sameLane) {
                $W = $slice * $slice_length + $index - 1;
            } else {
                if ($index == 0) {
                    $W = $slice * $slice_length - 1;
                } else {
                    $W = $slice * $slice_length;
                }
            }
        } else {
            if ($sameLane) {
                $W = 3 * $slice_length + $index - 1;
            } else {
                if ($index == 0) {
                    $W = 3 * $slice_length - 1;
                } else {
                    $W = 3 * $slice_length;
                }
            }
        }
        // Determine with the given non-equilibrium distribution which block is randomly selected from referencable blocks
        $J1 = $block[0][1];
        $x = $this->multiply($J1, $J1)[0];
        $y = $this->multiply($W, $x)[0];
        $relative_position = $W - 1 - $y;
        // Determine the absolute position of the block
        if ($passes == 0 || $slice == 3) {
            return $relative_position;
        } else {
            $start_position = $slice_length * ($slice + 1);
            return ($start_position + $relative_position) % (4 * $slice_length);
        }

    }

    /**
     * Calculates a hash with a variable output size
     *
     * @param string $data Data to hash
     * @param int $output_length Output size
     * @return string Hash
     */
    protected function variable_length_hash_function(string $data, int $output_length): string
    {
        // If the output size is < 64 bytes, the hash is calculated directly with Blake2b
        if ($output_length <= 64) {
            return $this->blake->hash($this->le32($output_length) . $data, $output_length);
        }
        // If the output size is > 64-bytes Blake2b is executed iteratively until the desired output size of the hash is reached
        $r = ((int)ceil(($output_length / 32))) - 2;
        $v = new SplFixedArray($r + 1);
        $v[0] = $this->blake->hash($this->le32($output_length) . $data, 64);
        for ($i = 1; $i < $r; $i++) {
            $v[$i] = $this->blake->hash($v[$i - 1], 64);
        }
        $v[$r] = $this->blake->hash($v[$r - 1], $output_length - 32 * $r);
        $output_hash = "";
        for ($i = 0; $i < $r; $i++) {
            $output_hash = $output_hash . substr($v[$i], 0, 32);
        }
        return $output_hash . $v[$r];
    }

    /**
     * Multiply two unsigned 32-Bit numbers and return the result as an array of two unsigned 32-Bit integer
     *
     * @param int $x Block with 1-KiB random data in 128 64-Bit integers
     * @param int $x Block with 1-KiB random data in 128 64-Bit integers
     * @return SplFixedArray Resulting unsigned 64-Bit integer as an array of two 32-Bit unsigned 32-Bit integer
     */
    protected function multiply(int $x, int $y):SplFixedArray
    {
        $hx = $x >> 16;    // Most significant 16 bits of x
        $lx = $x & 0xFFFF; // Least significant 16 bits of x
        $hy = $y >> 16;    // Most significant 16 bits of y
        $ly = $y & 0xFFFF; // Least significant 16 bits of y

        $hz = $hx * $hy;   // Most significant 32 bits of z = x * y = hz + lz + midz
        $lz = $lx * $ly;   // Least significant 32 bits of z = x * y - hz + lz + midz

        $midz = ($hx * $ly + $lx * $hy) << 16;
        $lmidz = $midz & 0xFFFFFFFF; // Least significant 32 bits of midz
        $hmidz = $midz >> 32; // Most significant 32 bits of midz

        return $this->new64(($hz + $hmidz) + (($lz + $lmidz) >> 32), ($lz + $lmidz) & 0xFFFFFFFF);
    }

    /**
     * Compression function G calculates a new block from two blocks
     *
     * @param SplFixedArray $X Unsigned 32-Bit integer
     * @param SplFixedArray $X Unsigned 32-Bit integer
     * @return SplFixedArray Resulting new Block with 1-KiB random data in 128 64-bit integers
     */
    protected function G(SplFixedArray $X, SplFixedArray $Y):SplFixedArray
    {
        $Z = $this->xor_int_block_array($X, $Y);
        // Permutation row
        for ($i = 0; $i < 8; $i++) {
            $this->P($Z, $i * 16, $i * 16 + 1, $i * 16 + 2, $i * 16 + 3, $i * 16 + 4, $i * 16 + 5, $i * 16 + 6, $i * 16 + 7, $i * 16 + 8, $i * 16 + 9, $i * 16 + 10, $i * 16 + 11, $i * 16 + 12, $i * 16 + 13, $i * 16 + 14, $i * 16 + 15);
        }
        // Permutation column
        for ($i = 0; $i < 8; $i++) {
            $this->P($Z, $i * 2, $i * 2 + 1, $i * 2 + 16, $i * 2 + 17, $i * 2 + 32, $i * 2 + 33, $i * 2 + 48, $i * 2 + 49, $i * 2 + 64, $i * 2 + 65, $i * 2 + 80, $i * 2 + 81, $i * 2 + 96, $i * 2 + 97, $i * 2 + 112, $i * 2 + 113);
        }
        return $this->xor_int_block_array($this->xor_int_block_array($X, $Y), $Z);
    }

    /**
     * The permutation function P permutes a block using the BlakMka round function
     *
     * @param SplFixedArray $block Block with 1-KiB random data in 128 64-Bit integers
     * @param int $v0 - v15  Positions of the unsigned 64-bit integers in the array
     */
    protected function P(SplFixedArray $block, int $v0, int $v1, int $v2, int $v3, int $v4, int $v5, int $v6, int $v7, int $v8, int $v9, int $v10, int $v11, int $v12, int $v13, int $v14, int $v15)
    {
        $this->BlaMka_round_function($block, $v0, $v4, $v8, $v12);
        $this->BlaMka_round_function($block, $v1, $v5, $v9, $v13);
        $this->BlaMka_round_function($block, $v2, $v6, $v10, $v14);
        $this->BlaMka_round_function($block, $v3, $v7, $v11, $v15);
        $this->BlaMka_round_function($block, $v0, $v5, $v10, $v15);
        $this->BlaMka_round_function($block, $v1, $v6, $v11, $v12);
        $this->BlaMka_round_function($block, $v2, $v7, $v8, $v13);
        $this->BlaMka_round_function($block, $v3, $v4, $v9, $v14);
    }

    /**
     * BlakMka round function which permutes four unsigned 64-bit integers
     *
     * @param SplFixedArray $block Block with 1-KiB random data in 128 64-Bit integers
     * @param int $a Positions of the unsigned 64-bit integer in the array
     * @param int $b Positions of the unsigned 64-bit integer in the array
     * @param int $c Positions of the unsigned 64-bit integer in the array
     * @param int $d Positions of the unsigned 64-bit integer in the array
     */
    protected function BlaMka_round_function(SplFixedArray $block, int $a, int $b, int $c, int $d)
    {
        $block[$a] = $this->add364($block[$a], $block[$b], $this->fBlaMka($block, $a, $b));
        $block[$d] = $this->rotr64($this->xor64($block[$d], $block[$a]), 32);
        $block[$c] = $this->add364($block[$c], $block[$d], $this->fBlaMka($block, $c, $d));
        $block[$b] = $this->rotr64($this->xor64($block[$b], $block[$c]), 24);
        $block[$a] = $this->add364($block[$a], $block[$b], $this->fBlaMka($block, $a, $b));
        $block[$d] = $this->rotr64($this->xor64($block[$d], $block[$a]), 16);
        $block[$c] = $this->add364($block[$c], $block[$d], $this->fBlaMka($block, $c, $d));
        $block[$b] = $this->rotr64($this->xor64($block[$b], $block[$c]), 63);
    }

    /**
     * Takes two blocks, combines them by an XOR operation and returns a new resulting block
     *
     * @param SplFixedArray $blockA Block with 1-KiB random data in 128 64-Bit integers
     * @param SplFixedArray $blockB Block with 1-KiB random data in 128 64-Bit integers
     * @return SplFixedArray Resulting Block with 1-KiB random data in 128 64-Bit integers
     */
    protected function xor_int_block_array(SplFixedArray $blockA, SplFixedArray $blockB): SplFixedArray
    {
        $new_int_64_block = new SplFixedArray(128);
        for ($i = 0; $i < 128; $i++) {
            $new_int_64_block[$i] = $this->new64($blockA[$i][0] ^ $blockB[$i][0], $blockA[$i][1] ^ $blockB[$i][1]);
        }
        return $new_int_64_block;
    }

    /**
     * Converts a string of 1024-Bytes into an array of 128 unsigned 64-Bit integers
     * The bytes in the string are considered in Little-Endian byte order
     *
     * @param string $block 1024-Bytes data
     * @return SplFixedArray Resulting Block with 128 64-Bit integers
     */
    protected function convert_string_block_to_int64_array(string $block): SplFixedArray
    {
        $new_int_64_block = new SplFixedArray(128);
        for ($i = 0; $i < 128; $i++) {
            $new_int_64_block[$i] = $this->new64(unpack('V', substr($block, $i * 8 + 4, 4))[1], unpack('V', substr($block, $i * 8, 4))[1]);
        }
        return $new_int_64_block;
    }

    /**
     * Converts a block of 128 unsigned 64-bit integers into a string
     * The numbers are stored in Little-Endian byte order in the string
     *
     * @param SplFixedArray $block Block with 128 64-Bit integers
     * @return string Resulting String with 1024-Bytes
     */
    protected function convert_int64_array_to_string(SplFixedArray $block): string
    {
        $new_string_block = "";
        for ($i = 0; $i < 128; $i++) {
            $new_string_block = $new_string_block . pack('V', $block[$i][1]) . pack('V', $block[$i][0]);
        }
        return $new_string_block;
    }

    /**
     * Creates an array from two unsigned 32-bit numbers that emulates an unsigned 64-Bit number
     *
     * @param int $high Unsigned 32-Bit integer in the array
     * @param int $low Unsigned 32-Bit integer in the array
     * @return SplFixedArray Resulting unsigned 64-Bit number as an array of two unsigned 32-Bit integer
     */
    protected function new64($high, $low): SplFixedArray
    {
        $i64 = new SplFixedArray(2);
        $i64[0] = $high & 0xffffffff;
        $i64[1] = $low & 0xffffffff;
        return $i64;
    }

    /**
     * Multiply two unsigned 32-bit numbers and then multiply the result by two and return the resulting unsigned 64-Bit number as an array of two unsigned 32-Bit integer
     *
     * @param SplFixedArray $block Block with 1-KiB random data in 128 64-Bit integers
     * @param int $a Positions of the unsigned 64-Bit integer in the array
     * @param int $b Positions of the unsigned 64-Bit integer in the array
     * @return SplFixedArray Resulting unsigned 64-Bit number as an array of two unsigned 32-Bit integer
     */
    protected function fBlaMka($block, $a, $b): SplFixedArray
    {
        $ab = $this->multiply($block[$a][1], $block[$b][1]);
        $mid = $ab[1] >> 31;
        $ab[1] = ($ab[1] << 1) & 0xFFFFFFFF;
        $ab[0] = (($ab[0] << 1) & 0xFFFFFFFF) + $mid;
        return $ab;
    }

}