namespace StatusCodes
{
    static class StatusCode
    {
        public const int ALLOW = 0; // ALLOW TRAFFIC THROUGH.
        public const int BLOCK = 1; // BLOCK TRAFFIC.
        public const int ACCUMULATE = 2; // REASSEMBLE MESSAGE.
        public const int MODIFY = 3; // MODIFY REQUEST/RESPONSE.
    }
}
