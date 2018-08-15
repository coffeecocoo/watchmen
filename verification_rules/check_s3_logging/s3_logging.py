# Copyright 2017 Insurance Australia Group Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

"""Facilitates checking S3 bucket policies for encryption"""

import json

from botocore.exceptions import ClientError

class S3Encryption(object):
    """
    Provides the list of S3 buckets that are compliant.
    Attributes:
      b3_s3_client: Boto3 S3 client.
    """
    def __init__(self, b3_s3_client):
        """Constructor"""
        self.client = b3_s3_client
        self.s3_bucket_list = self.client.list_buckets()['Buckets']

    def get_s3_bucket_logging(self, s3_bucket_name):
        """Retrieves policies attached to specified S3 bucket

        Args:
            s3_bucket_name: S3 Bucket name
        Returns:
            Policy statement
        """
        try:
            s3_bucket_logging = self.client.get_bucket_logging(Bucket=s3_bucket_name)

        except:
            s3_bucket_logging = []

        if s3_bucket_logging == []:
            logging_statement = []
        else:
            logging_statement = json.loads(s3_bucket_logging['LoggingEnabled'])

        return logging_statement


    def get_logging_comp_s3_bucket_list(self):
        """Get the list of compliant S3 Buckets

        Returns:
            List of S3 buckets
        """
        compliant_s3_bucket_list = []

        for s3_bucket_name in self.s3_bucket_list:
            logging_statements = self.get_s3_bucket_logging(s3_bucket_name['Name'])

            compliant_s3_bucket_list.append(
                self.get_encr_policy_bucket_list(s3_bucket_name['Name'], logging_statements)
            )

            compliant_s3_bucket_list.append(
                self.get_default_encr_bucket_list(s3_bucket_name['Name'])
            )

        return list(set([i for i in compliant_s3_bucket_list if i is not None]))