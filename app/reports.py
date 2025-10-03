import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, date
from sqlalchemy import func, extract, and_
from app.models import PatientVisit, MedicalRecord
from collections import Counter

def generate_patient_visits_by_month_chart():
    """
    Generate a bar chart showing number of patients by month for 2025
    using data from patient_visits table
    """
    try:
        # Query patient visits for 2025, grouped by month
        visits_data = PatientVisit.query.filter(
            extract('year', PatientVisit.visit_date) == 2025
        ).with_entities(
            extract('month', PatientVisit.visit_date).label('month'),
            func.count(PatientVisit.patient_id).label('patient_count')
        ).group_by(
            extract('month', PatientVisit.visit_date)
        ).all()
        
        # Create a dictionary to hold month data
        month_names = [
            'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
            'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'
        ]
        
        # Initialize data for all months
        months = []
        patient_counts = []
        
        # Create a lookup for existing data
        visit_dict = {int(month): count for month, count in visits_data}
        
        # Fill data for all 12 months
        for i in range(1, 13):
            months.append(month_names[i-1])
            patient_counts.append(visit_dict.get(i, 0))
        
        # Create the bar chart
        fig = go.Figure(data=[
            go.Bar(
                x=months,
                y=patient_counts,
                marker_color='rgb(55, 83, 109)',
                text=patient_counts,
                textposition='auto',
            )
        ])
        
        fig.update_layout(
            title={
                'text': 'Patient Visits by Month - 2025',
                'x': 0.5,
                'xanchor': 'center'
            },
            xaxis_title='Month',
            yaxis_title='Number of Patients',
            showlegend=False,
            height=500,
            margin=dict(l=50, r=50, t=80, b=50)
        )
        
        # Convert to HTML
        return fig.to_html(full_html=False, include_plotlyjs='cdn')
        
    except Exception as e:
        print(f"Error generating patient visits chart: {e}")
        return f"<div class='alert alert-danger'>Error generating chart: {str(e)}</div>"


def generate_icd10_codes_pie_chart():
    """
    Generate a pie chart showing distribution of ICD-10 codes for 2025
    using data from medical_records table
    """
    try:
        # Query medical records for 2025 with ICD-10 codes
        records_data = MedicalRecord.query.filter(
            and_(
                MedicalRecord.examined_date >= date(2025, 1, 1),
                MedicalRecord.examined_date <= date(2025, 12, 31),
                MedicalRecord.icd_10_code.isnot(None),
                MedicalRecord.icd_10_code != ''
            )
        ).with_entities(MedicalRecord.icd_10_code).all()
        
        if not records_data:
            return "<div class='alert alert-info'>No medical records with ICD-10 codes found for 2025.</div>"
        
        # Count occurrences of each ICD-10 code
        icd_codes = [record.icd_10_code for record in records_data]
        icd_counter = Counter(icd_codes)
        
        # Get the most common codes (limit to top 10 for readability)
        top_codes = icd_counter.most_common(10)
        
        if not top_codes:
            return "<div class='alert alert-info'>No ICD-10 codes found for the specified period.</div>"
        
        codes = [code for code, count in top_codes]
        counts = [count for code, count in top_codes]
        
        # Create simplified descriptions for common ICD-10 codes
        icd_descriptions = {
            'Z00': 'General health exam',
            'J06': 'Upper respiratory infection',
            'K59': 'Digestive disorders',
            'M25': 'Joint disorders',
            'R50': 'Fever symptoms',
            'I10': 'Hypertension',
            'E11': 'Type 2 diabetes',
            'J45': 'Asthma',
            'M79': 'Soft tissue disorders',
            'R51': 'Headache',
            'Z51': 'Follow-up care',
            'N39': 'Urinary disorders',
            'L30': 'Skin conditions',
            'K30': 'Stomach problems',
            'F32': 'Depression'
        }
        
        # Create hover text with descriptions
        hover_text = []
        for code in codes:
            # Get first 3 characters for lookup
            code_prefix = code[:3] if len(code) >= 3 else code
            description = icd_descriptions.get(code_prefix, 'Medical condition')
            hover_text.append(f"{code}: {description}")
        
        # Create the pie chart
        fig = go.Figure(data=[
            go.Pie(
                labels=codes,
                values=counts,
                hovertext=hover_text,
                hovertemplate='<b>%{label}</b><br>%{hovertext}<br>Count: %{value}<br>Percentage: %{percent}<extra></extra>',
                textinfo='label+percent',
                textposition='auto'
            )
        ])
        
        fig.update_layout(
            title={
                'text': 'Distribution of ICD-10 Codes - 2025',
                'x': 0.5,
                'xanchor': 'center'
            },
            height=600,
            margin=dict(l=50, r=50, t=80, b=50),
            showlegend=True,
            legend=dict(
                orientation="v",
                yanchor="middle",
                y=0.5,
                xanchor="left",
                x=1.01
            )
        )
        
        # Add annotation with legend information
        legend_text = "Common ICD-10 Code Meanings:<br>"
        for code in codes[:5]:  # Show top 5 in annotation
            code_prefix = code[:3] if len(code) >= 3 else code
            description = icd_descriptions.get(code_prefix, 'Medical condition')
            legend_text += f"• {code}: {description}<br>"
        
        fig.add_annotation(
            text=legend_text,
            xref="paper", yref="paper",
            x=0.02, y=0.02,
            xanchor="left", yanchor="bottom",
            showarrow=False,
            font=dict(size=10),
            bgcolor="rgba(255,255,255,0.8)",
            bordercolor="rgba(0,0,0,0.2)",
            borderwidth=1
        )
        
        # Convert to HTML
        return fig.to_html(full_html=False, include_plotlyjs='cdn')
        
    except Exception as e:
        print(f"Error generating ICD-10 codes chart: {e}")
        return f"<div class='alert alert-danger'>Error generating chart: {str(e)}</div>"


def get_available_reports():
    """
    Return a list of available reports with their metadata
    This makes it easy to add new reports in the future
    """
    return [
        {
            'id': 'patient_visits_by_month',
            'title': 'Patient Visits by Month (2025)',
            'description': 'Bar chart showing the number of patient visits for each month in 2025',
            'function': generate_patient_visits_by_month_chart,
            'icon': 'fa-chart-bar'
        },
        {
            'id': 'icd10_codes_distribution',
            'title': 'ICD-10 Codes Distribution (2025)',
            'description': 'Pie chart showing the distribution of ICD-10 codes in medical records for 2025',
            'function': generate_icd10_codes_pie_chart,
            'icon': 'fa-chart-pie'
        }
    ]


def generate_report(report_id):
    """
    Generate a specific report by ID
    """
    reports = get_available_reports()
    report = next((r for r in reports if r['id'] == report_id), None)
    
    if not report:
        return "<div class='alert alert-danger'>Report not found.</div>"
    
    return report['function']()