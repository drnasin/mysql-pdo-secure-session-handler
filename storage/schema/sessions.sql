--
-- Table structure for table `sessions`
--

CREATE TABLE `sessions` (
  `session_id` varchar(63) NOT NULL,
  `session_data` text NOT NULL,
  `modified` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `lifetime` int(11) NOT NULL,
  `init_vector` varbinary(130) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `sessions`
--
ALTER TABLE `sessions`
  ADD UNIQUE KEY `session_id` (`session_id`);