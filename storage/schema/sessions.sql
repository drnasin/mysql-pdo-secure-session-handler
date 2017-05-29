--
-- Table structure for table `sessions`
--

CREATE TABLE `sessions_test` (
  `session_id` varchar(40) NOT NULL,
  `session_data` text NOT NULL,
  `modified` timestamp NOT NULL,
  `lifetime` int(11) NOT NULL,
  `iv` VARBINARY(16) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `sessions`
--
ALTER TABLE `sessions`
  ADD UNIQUE KEY `session_id` (`session_id`);