# from flask import Flask, request, jsonify
# import boto3
# from botocore.exceptions import ClientError

# app = Flask(__name__)

# # Initialize DynamoDB resource
# dynamodb = boto3.resource('dynamodb')
# table = dynamodb.Table('Employee')  # Replace with your DynamoDB table name

# class DynamoDBAPI:
#     def __init__(self):
#         self.table = table
    
#     def query_dynamodb(self, partition_key=None, sort_key=None, filter_expression=None, projection_expression=None, limit=10):
#         # Prepare the key condition expression and attribute values
#         key_condition_expression = None
#         expression_attribute_values = {}

#         if partition_key:
#             key_condition_expression = 'partition_key = :partition_key'
#             expression_attribute_values[':partition_key'] = partition_key

#             if sort_key:
#                 key_condition_expression += ' AND sort_key = :sort_key'
#                 expression_attribute_values[':sort_key'] = sort_key

#         # Initialize the query parameters
#         query_params = {
#             'KeyConditionExpression': key_condition_expression,
#             'ExpressionAttributeValues': expression_attribute_values,
#             'Limit': limit
#         }

#         # Add filter expression if provided
#         if filter_expression:
#             query_params['FilterExpression'] = filter_expression

#         # Add projection expression if provided
#         if projection_expression:
#             query_params['ProjectionExpression'] = projection_expression

#         try:
#             # Execute the query
#             response = self.table.query(**query_params)
#             return response['Items'], response.get('Count', 0), response.get('ScannedCount', 0)
#         except ClientError as e:
#             return None, str(e), None

# class DynamoDBEndpoint:
#     def __init__(self):
#         self.api = DynamoDBAPI()

#     def handle_request(self):
#         # Get the query parameters from the request
#         partition_key = request.args.get('partition_key')
#         sort_key = request.args.get('sort_key')
#         filter_expression = request.args.get('filter_expression')
#         projection_expression = request.args.get('projection_expression')
#         limit = int(request.args.get('limit', 10))  # Default limit is 10

#         # Call the DynamoDB API with provided parameters
#         items, count, scanned_count = self.api.query_dynamodb(
#             partition_key=partition_key,
#             sort_key=sort_key,
#             filter_expression=filter_expression,
#             projection_expression=projection_expression,
#             limit=limit
#         )

#         # Return response
#         if items is not None:
#             return jsonify({
#                 'items': items,
#                 'count': count,
#                 'scanned_count': scanned_count
#             }), 200
#         else:
#             return jsonify({'error': scanned_count}), 500

# # Initialize the API endpoint
# dynamodb_endpoint = DynamoDBEndpoint()

# # Define the API endpoint to handle the query
# @app.route('/query', methods=['GET'])
# def query():
#     return dynamodb_endpoint.handle_request()

# if __name__ == '__main__':
#     app.run(debug=True)


# from flask import Config, Flask, request, jsonify
# import boto3
# from botocore.exceptions import ClientError

# app = Flask(__name__)

# # Initialize DynamoDB resource
# #dynamodb = boto3.resource('dynamodb')
# dynamodb = boto3.resource(
#     'dynamodb',
#     region_name='us-east-1',  # e.g., us-east-1
#     aws_access_key_id='kk9coe',
#     aws_secret_access_key='s6kjo4',
#     endpoint_url="http://localhost:8000",
#     # config=Config(
#     #     retries={'max_attempts': 10, 'mode': 'standard'}
#     # )
# )
# table = dynamodb.Table('Employee')  # Replace with your DynamoDB table name

# # print(table.get_item(Key={'LoginAlias': 'johns'}))

# class DynamoDBAPI:
#     def __init__(self):
#         self.table = table
    
#     def query_dynamodb(self, partition_key=None, sort_key=None, filter_expression=None, projection_expression=None, limit=10):
#         # Ensure partition key is provided
#         if not partition_key:
#             return None, "partition_key is required", None
        
#         # Prepare the key condition expression and attribute values
#         key_condition_expression = 'partition_key = :partition_key'
#         expression_attribute_values = {':partition_key': partition_key}

#         if sort_key:
#             key_condition_expression += ' AND sort_key = :sort_key'
#             expression_attribute_values[':sort_key'] = sort_key

#         # Initialize the query parameters
#         query_params = {
#             'KeyConditionExpression': key_condition_expression,
#             'ExpressionAttributeValues': expression_attribute_values,
#             'Limit': limit
#         }

#         # Add filter expression if provided
#         if filter_expression:
#             query_params['FilterExpression'] = filter_expression

#         # Add projection expression if provided
#         if projection_expression:
#             query_params['ProjectionExpression'] = projection_expression

#         try:
#             # Execute the query
#             response = self.table.query(**query_params)
#             return response['Items'], response.get('Count', 0), response.get('ScannedCount', 0)
#         except ClientError as e:
#             return None, f"Error querying DynamoDB: {str(e)}", None

# class DynamoDBEndpoint:
#     def __init__(self):
#         self.api = DynamoDBAPI()

#     def handle_request(self):
#         # Get the query parameters from the request
#         partition_key = request.args.get('partition_key')
#         sort_key = request.args.get('sort_key')
#         filter_expression = request.args.get('filter_expression')
#         projection_expression = request.args.get('projection_expression')
#         limit = int(request.args.get('limit', 10))  # Default limit is 10

#         # Call the DynamoDB API with provided parameters
#         items, error_message, scanned_count = self.api.query_dynamodb(
#             partition_key=partition_key,
#             sort_key=sort_key,
#             filter_expression=filter_expression,
#             projection_expression=projection_expression,
#             limit=limit
#         )

#         # Return response
#         if items is not None:
#             return jsonify({
#                 'items': items,
#                 'count': len(items),
#                 'scanned_count': scanned_count
#             }), 200
#         else:
#             return jsonify({'error': error_message}), 400

# # Initialize the API endpoint
# dynamodb_endpoint = DynamoDBEndpoint()

# # Define the API endpoint to handle the query
# @app.route('/query', methods=['GET'])
# def query():
#     return dynamodb_endpoint.handle_request()

# if __name__ == '__main__':
#     app.run(debug=True)


from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Attr, Key
import boto3
import re


class MasterTable:
    
    def __init__(cls, table_name: str):
        cls.table_name = table_name
        #print(table_name)

    dynamodb = boto3.resource(
        "dynamodb",
        region_name="us-east-1",
        aws_access_key_id="kk9coe",  # Dummy values for local DynamoDB
        aws_secret_access_key="s6kjo4",  # Dummy values for local DynamoDB
        endpoint_url="http://localhost:8000",  # Local DynamoDB endpoint
    )

    @staticmethod
    def build_condition_expression(attribute, operator, value, condition_type):
        """
        Build a condition expression for DynamoDB queries.
        Parameters:
        - attribute: The attribute name.
        - operator: The condition operator ('eq', 'lt', 'gt', 'contains', etc.).
        - value: The value for the condition.
        - condition_type: 'filter' for attributes, 'key' for partition/sort keys.

        Returns:
        - The constructed condition expression.
        """
        condition_mapping = {
            "eq": lambda attr, val: (
                Attr(attr).eq(val) if condition_type == "filter" else Key(attr).eq(val)
            ),
            "lt": lambda attr, val: (
                Attr(attr).lt(val) if condition_type == "filter" else Key(attr).lt(val)
            ),
            "lte": lambda attr, val: (
                Attr(attr).lte(val)
                if condition_type == "filter"
                else Key(attr).lte(val)
            ),
            "gt": lambda attr, val: (
                Attr(attr).gt(val) if condition_type == "filter" else Key(attr).gt(val)
            ),
            "gte": lambda attr, val: (
                Attr(attr).gte(val)
                if condition_type == "filter"
                else Key(attr).gte(val)
            ),
            "contains": lambda attr, val: Attr(attr).contains(val),
            "begins_with": lambda attr, val: Attr(attr).begins_with(val),
        }

        if operator not in condition_mapping:
            raise ValueError(f"Unsupported operator: {operator}")

        return condition_mapping[operator](attribute, value)

    def get_table(cls):
        """Returns the DynamoDB table resource."""
        #print(cls.table_name)
        return cls.dynamodb.Table(cls.table_name)

    def create(cls, **kwargs):
        """Create a new item in the table."""
        table = cls.get_table()
        try:
            table.put_item(Item=kwargs)
            return kwargs
        except ClientError as e:
            raise Exception(f"Create failed: {e.response['Error']['Message']}")

    def get(cls, **key):
        """Retrieve an item by its key."""
        table = cls.get_table()
        try:
            response = table.get_item(Key=key, ConsistentRead=True)
            return response.get("Item")  # Returns None if not found
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return None
            raise Exception(f"Retrieve failed: {e.response['Error']['Message']}")

    def filter(
        cls,
        partition_key=None,
        sort_key=None,
        filter_conditions=None,
        **attribute_values,
    ):
        """
        Filters items from the table based on a partition key, sort key, and attribute values.

        Parameters:
        - partition_key: The value of the partition key (if applicable).
        - sort_key: The value of the sort key (optional).
        - filter_conditions: List of additional filter conditions (optional).
                            Format: [(attribute, operator, value), ...].
        - attribute_values: Key-value pairs for filtering.

        Returns:
        - List of items matching the filter criteria.
        """
        table = cls.get_table()
        key_condition_expression = None
        filter_expression = None

        # Construct KeyConditionExpression for partition and sort keys
        if partition_key:
            key_condition_expression = Key(cls.partition_key).eq(partition_key)
            if sort_key:
                key_condition_expression &= Key(cls.sort_key).eq(sort_key)

        # Build the filter expression dynamically for attributes
        for attr, value in attribute_values.items():
            condition = Attr(attr).eq(value)
            filter_expression = (
                condition
                if filter_expression is None
                else filter_expression & condition
            )

        # Add any additional custom filter conditions
        if filter_conditions:
            for attr, operator, value in filter_conditions:
                condition = cls.build_condition_expression(
                    attr, operator, value, "filter"
                )
                filter_expression = (
                    condition
                    if filter_expression is None
                    else filter_expression & condition
                )

        try:
            # Execute the query or scan based on key condition presence
            if key_condition_expression:
                response = table.query(
                    KeyConditionExpression=key_condition_expression,
                    FilterExpression=filter_expression if filter_expression else None,
                )
            else:
                response = table.scan(FilterExpression=filter_expression)

            return response.get("Items", [])
        except ClientError as e:
            raise Exception(f"Filter failed: {e.response['Error']['Message']}")

    def update(cls, key, **kwargs):
        """
        Update an item in the table.
        Parameters:
            key: dict containing the key attributes (partition key and, if applicable, sort key).
            kwargs: attributes to update.
        """
        table = cls.get_table()
        print("kwargs is",kwargs)
        try:
            print("UpdateExpression is {0}".format("SET " + ", ".join(f"{k}=:{k}" for k in kwargs)))
            expression_attribute_values = {f":{k}": v for k, v in kwargs.items()}
            print("ExpressionAttributeValues is {0}".format(expression_attribute_values))
            table.update_item(
                Key=key,
                UpdateExpression="SET " + ", ".join(f"{k}=:{k}" for k in kwargs),
                ExpressionAttributeValues={f":{k}": v for k, v in kwargs.items()},
                ReturnValues="UPDATED_NEW",
            )
            #print("a is",a)
            return kwargs
        except ClientError as e:
            raise Exception(f"Update failed: {e.response['Error']['Message']}")

    def delete(cls, **key):
        """Delete an item from the table."""
        table = cls.get_table()
        try:
            table.delete_item(Key=key)
            return True
        except ClientError as e:
            raise Exception(f"Delete failed: {e.response['Error']['Message']}")



# class User(MasterTable):
#     def __init__(self):
#         super().__init__(table_name="Employee")




from flask import Flask, request, jsonify
#from your_module import MasterTable  # Replace `your_module` with the actual filename

# Initialize Flask app
app = Flask(__name__)

# Initialize MasterTable with a table name
# MasterTable.table_name = "Employee"  # Replace with your DynamoDB table name
#MasterTable("Employee")

@app.route('/create', methods=['POST'])
def create_item():
    data = request.json
    print("data is",data)
    try:
        item = MasterTable("Employee").create(**data)
        return jsonify({"message": "Item created successfully", "item": item}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# @app.route('/get', methods=['GET'])
# def get_item():
#     key = request.args.to_dict()
#     print("key is",key)
#     try:
#         item = MasterTable("Employee").get(**key)
#         if item:
#             return jsonify(item), 200
#         return jsonify({"message": "Item not found"}), 404
#     except Exception as e:
#         return jsonify({"error": str(e)}), 400


@app.route('/get', methods=['GET'])
def get_item():
    key = request.args.to_dict()
    #print("key is", key)
    try:
        item = MasterTable("Employee").get(**key)
        #print("item is", item)
        if item:
            # Convert any sets in the item to lists
            serialized_item = {k: list(v) if isinstance(v, set) else v for k, v in item.items()}
            #print("serialized_item is", serialized_item)
            return jsonify(serialized_item), 200
        return jsonify({"message": "Item not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/update', methods=['PUT'])
def update_item():
    data = request.json
    print("data is",data)
    key = data.get('key')  # Expecting 'key' to contain the key attributes
    print("key is",key)
    attributes = data.get('attributes')  # Attributes to update
    print("attributes is",attributes)
    
     # Validate input types
    if not isinstance(key, dict):
        return jsonify({"error": "Key must be a dictionary"}), 400
    if not isinstance(attributes, dict):
        return jsonify({"error": "Attributes must be a dictionary"}), 400
    

    if not key or not attributes:
        return jsonify({"error": "Key and attributes are required"}), 400

    try:
        updated_item = MasterTable("Employee").update(key, **attributes)
        return jsonify({"message": "Item updated successfully", "item": updated_item}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/delete', methods=['DELETE'])
def delete_item():
    key = request.json
    try:
        result = MasterTable("Employee").delete(**key)
        if result:
            return jsonify({"message": "Item deleted successfully"}), 200
        return jsonify({"message": "Item not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/filter', methods=['POST'])
def filter_items():
    data = request.json
    print("data is",data)
    partition_key = data.get("partition_key")
    sort_key = data.get("sort_key")
    filter_conditions = data.get("filter_conditions")
    attribute_values = data.get("attribute_values", {})

    try:
        items = MasterTable("Employee").filter(
            partition_key=partition_key,
            sort_key=sort_key,
            filter_conditions=filter_conditions,
            **attribute_values,
        )
        print("items is",items)
        serializable_items = [
            {k: list(v) if isinstance(v, set) else v for k, v in item.items()}
            for item in items
        ]
        print("serializable_items is",serializable_items)
        return jsonify({"items": serializable_items}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# Run the app
if __name__ == '__main__':
    app.run(debug=True)

