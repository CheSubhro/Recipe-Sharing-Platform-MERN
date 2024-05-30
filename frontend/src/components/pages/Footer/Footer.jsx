
import React from 'react';
import { Grid, Typography, Link } from '@mui/material';

const Footer = () => {
    return (
        <>
            <Grid container justifyContent="center" sx={{ backgroundColor: '#f0f0f0', padding: '20px 0' }}>
                <Typography variant="body1">
                    © 2024 &nbsp;
                    <Link href="#" color="error" underline="none">
                        InstaImageSave
                    </Link>
                    <span>&nbsp;•&nbsp;</span>
                    We Are Not affiliated with Meta Platforms, Inc. either.
                </Typography>
            </Grid>
        </>
    )
}

export default Footer